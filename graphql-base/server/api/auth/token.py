from datetime import datetime, timedelta, timezone
from jose import jwt
from server.api.settings import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from server.api.utils.logger import write_log, is_revoked, log_ttl_expiry
import uuid

MAX_TTL_SECONDS = 3600
REFRESH_TTL_SECONDS = 604800

def create_token_pair(user_id: str, role: str = "user", ttl_override: int = None, refresh_override: int = None):
    issued_at = datetime.now(timezone.utc)

    if ttl_override and ttl_override > MAX_TTL_SECONDS:
        ttl_override = MAX_TTL_SECONDS

    access_exp = issued_at + timedelta(seconds=ttl_override or ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    refresh_exp = issued_at + timedelta(seconds=refresh_override or REFRESH_TTL_SECONDS)
    trace_id = str(uuid.uuid4())

    access_payload = {
        "sub": user_id,
        "exp": access_exp,
        "iat": issued_at,
        "scope": "read write",
        "role": role,
        "trace_id": trace_id
    }

    refresh_payload = {
        "sub": user_id,
        "exp": refresh_exp,
        "iat": issued_at,
        "type": "refresh",
        "role": role,
        "trace_id": trace_id
    }

    access_token = jwt.encode(access_payload, SECRET_KEY, algorithm=ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm=ALGORITHM)

    write_log({
        "event": "token_issued",
        "user_id": user_id,
        "role": role,
        "scope": access_payload["scope"],
        "expires_at": access_exp.isoformat(),
        "refresh_expires_at": refresh_exp.isoformat(),
        "trace_id": trace_id,
        "timestamp": issued_at.isoformat()
    }, stream=role)

    log_ttl_expiry(user_id, role, trace_id, access_exp, token_type="access")
    log_ttl_expiry(user_id, role, trace_id, refresh_exp, token_type="refresh")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_at": access_exp.isoformat(),
        "expires_in": int((access_exp - datetime.now(timezone.utc)).total_seconds()),
        "issued_at": issued_at.isoformat(),
        "user_id": user_id,
        "scope": access_payload["scope"],
        "trace_id": trace_id
    }

def decode_token(token: str, expected_type: str = None):
    if is_revoked(token):
        write_log({
            "event": "token_decoded",
            "status": "error",
            "reason": "revoked"
        }, stream="security")
        return None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if expected_type and payload.get("type") != expected_type:
            write_log({
                "event": "token_decoded",
                "status": "error",
                "reason": "type mismatch",
                "expected": expected_type,
                "actual": payload.get("type"),
                "trace_id": payload.get("trace_id")
            }, stream=payload.get("role", "default"))
            return None

        write_log({
            "event": "token_decoded",
            "status": "success",
            "user_id": payload.get("sub"),
            "type": payload.get("type", "access"),
            "trace_id": payload.get("trace_id"),
            "role": payload.get("role")
        }, stream=payload.get("role", "default"))

        return payload

    except jwt.ExpiredSignatureError:
        write_log({
            "event": "token_decoded",
            "status": "error",
            "reason": "expired"
        }, stream="security")
        return None

    except jwt.JWTError as e:
        write_log({
            "event": "token_decoded",
            "status": "error",
            "reason": str(e),
            "token": token[:32] + "..."
        }, stream="security")
        return None

def has_scope(payload, required: str):
    scopes = payload.get("scope", "").split()
    return required in scopes
