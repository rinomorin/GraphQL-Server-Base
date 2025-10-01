# server/api/handlers/auth_handlers.py
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone
from flask import Request

from server.api.auth.token import (
    create_token_pair,
    refresh_token_flow,
    decode_token,
    has_scope,
)
from server.api.utils.logger import write_log, revoke_token, revoke_rotation_chain_atomic
from server.api.permissions import log_mutation, require_mutation_scope, allow_mutation

# Helpers to extract bearer token and caller payload from GraphQL context
def _caller_payload_from_info(info) -> Optional[Dict[str, Any]]:
    ctx = getattr(info, "context", {}) or {}
    token = ctx.get("token")
    if not token:
        return None
    payload = decode_token(token, verify_exp=True)
    return payload

# Resolver: login
def resolve_login(_, info, username: str, password: str, code_challenge: Optional[str] = None, code_challenge_method: Optional[str] = None):
    """
    Authenticate user (stubbed). On success return access+refresh pair.
    Replace the auth check with your real credential backend.
    """
    # Simple credential stub for local/dev; replace with real auth backend
    if username != "admin" and username != "user":
        log_mutation({"sub": username}, "login", "failed", "unknown_user")
        raise Exception("authentication_failed")

    # In a real system verify password, check MFA, etc.
    role = "admin" if username == "admin" else "user"
    scope = "admin:introspect user:refresh" if role == "admin" else "user:refresh read:profile"

    access_token, refresh_token, refresh_claims = create_token_pair(subject=username, scope=scope, role=role)

    log_mutation({"sub": username, "role": role}, "login", "success")
    write_log({
        "event": "login_issued",
        "sub": username,
        "role": role,
        "issued_at": datetime.now(timezone.utc).isoformat()
    }, stream=role)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_at": refresh_claims.get("exp"),
        "expires_in": None,
        "issued_at": refresh_claims.get("iat"),
        "user_id": username,
        "scope": scope
    }

# Resolver: refreshToken
def resolve_refresh_token(_, info, refresh_token: str, code_verifier: Optional[str] = None):
    caller_payload = _caller_payload_from_info(info)
    if not caller_payload:
        log_mutation({}, "refreshToken", "denied", "unauthenticated")
        raise Exception("unauthenticated")

    if not allow_mutation(caller_payload, "refreshToken") or not require_mutation_scope(caller_payload, "refreshToken"):
        log_mutation(caller_payload, "refreshToken", "denied", "insufficient_permissions")
        raise Exception("forbidden")

    try:
        access_token, new_refresh_token = refresh_token_flow(refresh_token, requester_payload=caller_payload)
    except Exception as e:
        write_log({
            "event": "refresh_error",
            "error": str(e),
            "caller_sub": caller_payload.get("sub") if isinstance(caller_payload, dict) else None
        }, stream=(caller_payload.get("role") if isinstance(caller_payload, dict) else "security"))
        log_mutation(caller_payload, "refreshToken", "failed", str(e))
        raise

    log_mutation(caller_payload, "refreshToken", "success")
    write_log({
        "event": "refresh_success",
        "caller_sub": caller_payload.get("sub"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }, stream=(caller_payload.get("role") if isinstance(caller_payload, dict) else "system"))

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token
    }

# Resolver: logout
def resolve_logout(_, info):
    caller_payload = _caller_payload_from_info(info)
    if not caller_payload:
        log_mutation({}, "logout", "denied", "unauthenticated")
        raise Exception("unauthenticated")

    # Ideally the client sends the refresh token to be revoked; here we attempt best-effort
    # If the context included a token, try to revoke it by jti
    token = info.context.get("token")
    jti = None
    if token:
        payload = decode_token(token, verify_exp=False)
        jti = payload.get("jti") if isinstance(payload, dict) else None

    try:
        revoke_token(token_str=token or "", jti=jti, initiator=caller_payload)
    except Exception as e:
        write_log({"event": "logout_revoke_error", "error": str(e), "user": caller_payload.get("sub")}, stream=caller_payload.get("role"))
        log_mutation(caller_payload, "logout", "failed", "revoke_error")
        raise

    log_mutation(caller_payload, "logout", "success")
    write_log({"event": "logout_success", "user": caller_payload.get("sub")}, stream=caller_payload.get("role"))
    return True

# Resolver: revokeToken (admin)
def resolve_revoke_token(_, info, token: str):
    caller_payload = _caller_payload_from_info(info)
    if not caller_payload:
        log_mutation({}, "revokeToken", "denied", "unauthenticated")
        raise Exception("unauthenticated")

    if not allow_mutation(caller_payload, "revokeToken") or not require_mutation_scope(caller_payload, "revokeToken"):
        log_mutation(caller_payload, "revokeToken", "denied", "insufficient_permissions")
        raise Exception("forbidden")

    # Try to extract jti for reliable revocation
    target_payload = decode_token(token, verify_exp=False)
    jti = target_payload.get("jti") if isinstance(target_payload, dict) else None

    ok = revoke_token(token_str=token, jti=jti, initiator=caller_payload)
    log_mutation(caller_payload, "revokeToken", "success" if ok else "failed", None if ok else "revoke_failed")
    return bool(ok)

# Resolver: revokeRotationChain (admin)
def resolve_revoke_rotation_chain(_, info, jti: str):
    caller_payload = _caller_payload_from_info(info)
    if not caller_payload:
        log_mutation({}, "revokeRotationChain", "denied", "unauthenticated")
        raise Exception("unauthenticated")

    if not allow_mutation(caller_payload, "revokeRotationChain") or not require_mutation_scope(caller_payload, "revokeRotationChain"):
        log_mutation(caller_payload, "revokeRotationChain", "denied", "insufficient_permissions")
        raise Exception("forbidden")

    try:
        revoked = revoke_rotation_chain_atomic(jti, initiator=caller_payload)
    except Exception as e:
        write_log({"event": "revoke_rotation_chain_error", "error": str(e), "initiator": caller_payload}, stream=caller_payload.get("role"))
        log_mutation(caller_payload, "revokeRotationChain", "failed", str(e))
        raise

    write_log({"event": "revoke_rotation_chain", "start_jti": jti, "revoked_count": len(revoked)}, stream=caller_payload.get("role"))
    log_mutation(caller_payload, "revokeRotationChain", "success")
    return revoked

# Resolver: me
def resolve_me(_, info):
    caller_payload = _caller_payload_from_info(info)
    if not caller_payload:
        return None
    return {
        "user_id": caller_payload.get("sub"),
        "scope": caller_payload.get("scope"),
        "issued_at": caller_payload.get("iat"),
        "trace_id": caller_payload.get("trace_id"),
        "role": caller_payload.get("role")
    }
