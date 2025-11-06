# server/api/handlers/auth_handlers.py
import json
import os
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone

import bcrypt
from flask import Request

from server.api.auth.token import (
    create_token_pair,
    refresh_token_flow,
    decode_token,
    has_scope,
)
from server.api.utils.logger import write_log, revoke_token, revoke_rotation_chain_atomic
from server.api.permissions import log_mutation, require_mutation_scope, allow_mutation

# Path to users DB JSON file; set USERS_DB_PATH env var or replace default with absolute path
USERS_DB_PATH = os.environ.get("USERS_DB_PATH", "/etc/myapp/users.db")

# Helpers to extract bearer token and caller payload from GraphQL context
def _caller_payload_from_info(info) -> Optional[Dict[str, Any]]:
    ctx = getattr(info, "context", {}) or {}
    token = ctx.get("token")
    if not token:
        return None
    payload = decode_token(token, verify_exp=True)
    return payload

# Helpers to load and verify users from a JSON users.db
def _load_user_record(username: str) -> Optional[Dict[str, Any]]:
    try:
        with open(USERS_DB_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        return None

    # Top-level keyed by username
    rec = db.get(username)
    if rec and isinstance(rec, dict):
        if "username" not in rec:
            rec["username"] = username
        return rec

    # Or find by internal username field
    for key, rec in db.items():
        if isinstance(rec, dict) and rec.get("username") == username:
            return rec

    return None

def _verify_password(hashed_password: str, password: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

# Resolver: login (replaced to consult users.db and verify bcrypt)
def resolve_login(_, info, username: str, password: str, code_challenge: Optional[str] = None, code_challenge_method: Optional[str] = None):
    """
    Authenticate user against users.db and return a full OAuth-style session object.
    """
    user_rec = _load_user_record(username)
    if not user_rec:
        log_mutation({"sub": username}, "login", "failed", "unknown_user")
        raise Exception("authentication_failed")

    hashed = user_rec.get("hashed_password") or user_rec.get("password_hash") or user_rec.get("password")
    if not hashed or not _verify_password(hashed, password):
        log_mutation({"sub": username}, "login", "failed", "bad_credentials")
        raise Exception("authentication_failed")

    roles = user_rec.get("roles", [])
    role = "admin" if "admin" in roles else (roles[0] if roles else "user")
    scope = "admin:introspect user:refresh" if "admin" in roles else "user:refresh read:profile"

    access_token, refresh_token, refresh_claims = create_token_pair(subject=username, scope=scope, role=role)

    now_ts = int(datetime.now(timezone.utc).timestamp())
    issued_at = None
    access_expires_at = None
    access_expires_in = None
    try:
        access_claims = decode_token(access_token, verify_exp=False)
        if isinstance(access_claims, dict):
            issued_at = access_claims.get("iat")
            access_expires_at = access_claims.get("exp")
            if isinstance(access_expires_at, int):
                access_expires_in = max(0, access_expires_at - now_ts)
    except Exception:
        issued_at = now_ts

    log_mutation({"sub": username, "role": role}, "login", "success")
    write_log({
        "event": "login_issued",
        "sub": username,
        "role": role,
        "issued_at": datetime.now(timezone.utc).isoformat()
    }, stream=role)

    # Return camelCase fields to match schema; also include snake_case for backwards compatibility
    return {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "tokenType": "Bearer",
        "issuedAt": issued_at,
        "expiresAt": access_expires_at,
        "expiresIn": access_expires_in,
        "scope": scope,
        "role": role,
        "userId": user_rec.get("id") or user_rec.get("user_id") or username,
        "chainId": refresh_claims.get("chain_id"),

        # backwards-compatible keys
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "issued_at": issued_at,
        "expires_at": access_expires_at,
        "expires_in": access_expires_in,
        "user_id": user_rec.get("id") or user_rec.get("user_id") or username,
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

# Resolver: authSession (new)
def resolve_auth_session(_, info):
    """
    Return an auth session object. Uses current auth context from info.context["token"].
    Only returns refresh token when caller is authorized (allow_mutation + require_mutation_scope).
    This issues a fresh token pair for the session metadata; replace with stored tokens if you track them server-side.
    """
    ctx = getattr(info, "context", {}) or {}
    caller_payload = _caller_payload_from_info(info)
    if not caller_payload:
        return None

    subject = caller_payload.get("sub")
    scope = caller_payload.get("scope", "") or ""
    role = caller_payload.get("role")

    access_token, refresh_token, refresh_claims = create_token_pair(subject=subject, scope=scope, role=role)

    issued_at = refresh_claims.get("iat")
    refresh_exp = refresh_claims.get("exp")
    now_ts = int(datetime.now(timezone.utc).timestamp())

    can_receive_refresh = False
    try:
        can_receive_refresh = allow_mutation(caller_payload, "refreshToken") and require_mutation_scope(caller_payload, "refreshToken")
    except Exception:
        can_receive_refresh = False

    access_expires_at = None
    access_expires_in = None
    try:
        access_claims = decode_token(access_token, verify_exp=False)
        if isinstance(access_claims, dict):
            access_expires_at = access_claims.get("exp")
            if isinstance(access_expires_at, int):
                access_expires_in = max(0, access_expires_at - now_ts)
    except Exception:
        access_expires_at = None
        access_expires_in = None

    return {
        "accessToken": access_token,
        "tokenType": "Bearer",
        "issuedAt": issued_at,
        "expiresAt": access_expires_at,
        "expiresIn": access_expires_in,
        "scope": scope,
        "role": role,
        "refreshToken": refresh_token if can_receive_refresh else None,
        "refreshExpiresAt": refresh_exp,
        "refreshExpiresIn": (refresh_exp - now_ts) if isinstance(refresh_exp, int) else None,
        "chainId": refresh_claims.get("chain_id"),
    }
