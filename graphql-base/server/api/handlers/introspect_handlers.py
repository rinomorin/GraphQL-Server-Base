# server/api/handlers/introspect_handlers.py
from typing import List, Dict, Any
from server.api.auth.token import decode_token  # must return payload or None
from server.api.permissions import allow_mutation, require_mutation_scope, log_mutation
from server.api.utils.logger import (
    get_redis,
    REVOKED_SET_KEY,
    USED_SET_KEY,
    ROTATED_MAP_KEY,
    is_jti_used,
    is_jti_rotated,
    is_revoked,
    write_log
)
from datetime import datetime, timezone

def _collect_lineage(redis_client, start_jti: str) -> List[str]:
    lineage = []
    seen = set()
    current = start_jti
    # Walk forward using rotated mapping values: start_jti -> child -> ...
    while True:
        next_jti = redis_client.hget(ROTATED_MAP_KEY, current)
        if not next_jti:
            break
        if next_jti in seen:
            write_log({"event": "introspect_lineage_cycle", "start_jti": start_jti, "cycle_jti": next_jti})
            break
        lineage.append(next_jti)
        seen.add(next_jti)
        current = next_jti
    return lineage

def resolve_introspect_token(_, info, token: str):
    # auth: require caller token and admin permissions
    caller_token = info.context.get("token")
    caller_payload = decode_token(caller_token) if caller_token else None
    if not caller_payload:
        log_mutation({}, "introspectToken", "denied", "missing caller token")
        return {
            "valid": False,
            "revoked": True,
            "used": False,
            "rotated": False,
            "lineage": [],
            "reason": "unauthenticated"
        }

    if not allow_mutation(caller_payload, "introspectToken") or not require_mutation_scope(caller_payload, "introspectToken"):
        log_mutation(caller_payload, "introspectToken", "denied", "insufficient permissions")
        return {
            "valid": False,
            "revoked": True,
            "used": False,
            "rotated": False,
            "lineage": [],
            "reason": "forbidden"
        }

    # decode target token without raising; decode_token should return None on invalid/expired
    target_payload = decode_token(token, allow_expired=True)  # allow_expired optional behaviour
    redis_client = get_redis()

    result: Dict[str, Any] = {
        "valid": False,
        "token_type": None,
        "payload": None,
        "revoked": False,
        "used": False,
        "rotated": False,
        "lineage": [],
        "issued_at": None,
        "expires_at": None,
        "reason": None
    }

    if not target_payload:
        # Could be invalid signature or malformed or missing jti; attempt best-effort extraction
        log_mutation(caller_payload, "introspectToken", "success", "introspected invalid token")
        result.update({"valid": False, "reason": "invalid_or_malformed"})
        return result

    # fill payload and timestamps
    result["valid"] = True
    result["payload"] = target_payload
    result["token_type"] = target_payload.get("typ") or target_payload.get("token_type")
    result["issued_at"] = target_payload.get("iat")
    result["expires_at"] = target_payload.get("exp")

    jti = target_payload.get("jti")
    if jti:
        result["revoked"] = bool(redis_client.sismember(REVOKED_SET_KEY, jti))
        result["used"] = bool(redis_client.sismember(USED_SET_KEY, jti))
        result["rotated"] = bool(redis_client.hexists(ROTATED_MAP_KEY, jti))
        result["lineage"] = _collect_lineage(redis_client, jti)
    else:
        result["reason"] = "no_jti_in_token"

    # Additional checks (example: cumulative lifetime)
    # If token contains chain_issued_at or similar, evaluate policy here and annotate result["reason"] or flags.

    # Audit the introspection call
    write_log({
        "event": "introspect_token",
        "caller_sub": caller_payload.get("sub"),
        "target_sub": target_payload.get("sub"),
        "target_jti": jti,
        "revoked": result["revoked"],
        "lineage_count": len(result["lineage"]),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }, stream=caller_payload.get("role", "admin"))

    log_mutation(caller_payload, "introspectToken", "success")
    return result
