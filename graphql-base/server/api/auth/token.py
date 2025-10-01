# server/api/auth/token.py
"""
Token utilities with hardened signing, verification, key manager integration,
atomic one-time-use enforcement, and chain TTL enforcement.

Exports:
- decode_token
- sign_jwt
- create_token_pair
- rotate_refresh_token_and_issue_pair
- refresh_token_flow
- has_scope
"""
from __future__ import annotations
import os
import time
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from jose import jwt, JWTError, ExpiredSignatureError

from server.api.utils.logger import write_log
from server.api.utils.revocation import (
    mark_jti_rotated,
    mark_jti_used,
    add_revoked,
    create_chain_meta,
    get_chain_meta,
    set_chain_revoked,
    consume_jti_atomically,
)
from server.api.utils.revocation import revoke_rotation_chain_atomic as revocation_revoke_chain
from server.api.utils.keys import get_key_manager

# Configuration
ENV = os.environ.get("ENV", "dev")
LEGACY_SECRET = os.environ.get("SECRET_KEY", "changeme-local-dev")
ALGORITHM = os.environ.get("JWT_ALG", "HS256")

ACCESS_TTL = int(os.environ.get("ACCESS_TTL", 300))
REFRESH_TTL = int(os.environ.get("REFRESH_TTL", 60 * 60 * 24))
MAX_CHAIN_LIFETIME_SECONDS = int(os.environ.get("MAX_CHAIN_LIFETIME_SECONDS", 7 * 24 * 3600))
CHAIN_METADATA_TTL = MAX_CHAIN_LIFETIME_SECONDS + 3600
ENFORCE_CHAIN_TTL = os.environ.get("ENFORCE_CHAIN_TTL", "1") == "1"

_key_manager = get_key_manager()

# Startup safety
if ENV != "dev":
    if not _key_manager.list_keys() and LEGACY_SECRET == "changeme-local-dev":
        raise RuntimeError("insecure default SECRET_KEY in non-dev; configure SIGNING_KEYS_JSON or use KeyManager")

def _new_jti() -> str:
    return str(uuid.uuid4())

def _now() -> int:
    return int(time.time())

# Centralized decode helper using KeyManager
def decode_token(token: str, verify_exp: bool = True, expected_typ: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        write_log({"event": "jwt_header_parse_error", "error": str(e), "token_snippet": (token or "")[:48]})
        return None

    kid = header.get("kid")
    key = _key_manager.get_key(kid) or LEGACY_SECRET
    options = {"verify_exp": verify_exp}

    try:
        payload = jwt.decode(token, key, algorithms=[ALGORITHM], options=options)
    except ExpiredSignatureError:
        write_log({"event": "token_expired", "token_snippet": (token or "")[:48], "kid": kid})
        return None
    except JWTError as e:
        write_log({"event": "token_decode_error", "error": str(e), "token_snippet": (token or "")[:48], "kid": kid})
        return None
    except Exception as e:
        write_log({"event": "token_decode_unexpected", "error": str(e), "token_snippet": (token or "")[:48], "kid": kid})
        return None

    if expected_typ:
        typ = payload.get("typ")
        if typ != expected_typ:
            write_log({"event": "token_typ_mismatch", "expected": expected_typ, "actual": typ, "token_jti": payload.get("jti")})
            return None

    return payload

# Signing helper with kid header via KeyManager
def sign_jwt(claims: Dict[str, Any], ttl: Optional[int] = None, kid: Optional[str] = None) -> str:
    payload = dict(claims)
    now = _now()
    payload.setdefault("iat", now)
    if ttl is not None:
        payload["exp"] = now + int(ttl)
    elif "exp" not in payload:
        payload["exp"] = now + ACCESS_TTL

    chosen_kid = kid or _key_manager.get_preferred() if hasattr(_key_manager, "get_preferred") else None
    key = _key_manager.get_key(chosen_kid) or LEGACY_SECRET
    headers = {}
    if chosen_kid:
        headers["kid"] = chosen_kid
    return jwt.encode(payload, key, algorithm=ALGORITHM, headers=headers)

# High-level token pair creator
def create_token_pair(subject: str, scope: str = "", role: Optional[str] = None) -> Tuple[str, str, Dict[str, Any]]:
    now = _now()
    access_jti = _new_jti()
    access_claims = {
        "sub": subject,
        "jti": access_jti,
        "typ": "access",
        "scope": scope,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TTL,
    }
    access_token = sign_jwt(access_claims, ttl=ACCESS_TTL)

    refresh_jti = _new_jti()
    chain_id = str(uuid.uuid4())
    chain_issued_at = now

    refresh_claims = {
        "sub": subject,
        "jti": refresh_jti,
        "typ": "refresh",
        "scope": scope,
        "role": role,
        "chain_id": chain_id,
        "chain_issued_at": chain_issued_at,
        "iat": now,
        "exp": now + REFRESH_TTL,
    }
    refresh_token = sign_jwt(refresh_claims, ttl=REFRESH_TTL)

    try:
        create_chain_meta(chain_id, refresh_jti, chain_issued_at, CHAIN_METADATA_TTL)
    except Exception as e:
        write_log({"event": "create_chain_meta_error", "error": str(e), "chain_id": chain_id})

    try:
        mark_jti_rotated(refresh_jti, refresh_jti)
    except Exception:
        pass

    write_log({
        "event": "issue_token_pair",
        "sub": subject,
        "access_jti": access_jti,
        "refresh_jti": refresh_jti,
        "chain_id": chain_id,
        "chain_issued_at": chain_issued_at
    }, stream=role or "system")

    return access_token, refresh_token, refresh_claims

# Rotation / refresh logic
def rotate_refresh_token_and_issue_pair(old_refresh_token: str, requester_payload: Optional[Dict[str, Any]] = None) -> Tuple[str, str, Dict[str, Any]]:
    old_claims = decode_token(old_refresh_token, verify_exp=False, expected_typ="refresh")
    if not old_claims:
        raise ValueError("invalid_refresh_token")

    old_jti = old_claims.get("jti")
    subject = old_claims.get("sub")
    scope = old_claims.get("scope", "")
    role = old_claims.get("role")
    chain_id = old_claims.get("chain_id")
    chain_issued_at = old_claims.get("chain_issued_at")
    now = _now()

    # Enforce chain TTL
    if ENFORCE_CHAIN_TTL:
        if chain_id:
            meta = get_chain_meta(chain_id)
            if meta and "chain_issued_at" in meta:
                try:
                    chain_issued_at = int(meta.get("chain_issued_at"))
                except Exception:
                    chain_issued_at = chain_issued_at
        if chain_issued_at and (chain_issued_at + MAX_CHAIN_LIFETIME_SECONDS) < now:
            write_log({
                "event": "refresh_denied_chain_ttl",
                "chain_id": chain_id,
                "target_jti": old_jti,
                "chain_issued_at": chain_issued_at,
                "now": now,
                "max_chain_lifetime": MAX_CHAIN_LIFETIME_SECONDS
            }, stream=(requester_payload.get("role") if isinstance(requester_payload, dict) else "security"))

            if chain_id:
                try:
                    set_chain_revoked(chain_id)
                except Exception:
                    pass
                origin_jti = None
                try:
                    origin_meta = meta or get_chain_meta(chain_id)
                    origin_jti = origin_meta.get("origin_jti") if origin_meta else None
                except Exception:
                    origin_jti = None

                try:
                    revocation_revoke_chain(origin_jti or old_jti, initiator={"role": "system", "reason": "chain_ttl_exceeded"})
                except Exception as e:
                    write_log({"event": "revoke_chain_on_ttl_error", "error": str(e), "chain_id": chain_id})

            raise ValueError("refresh_denied_chain_lifetime_exceeded")

    # Create new refresh token preserving chain_id and chain_issued_at
    new_refresh_jti = _new_jti()
    new_refresh_claims = {
        "sub": subject,
        "jti": new_refresh_jti,
        "typ": "refresh",
        "scope": scope,
        "role": role,
        "chain_id": chain_id,
        "chain_issued_at": chain_issued_at,
        "iat": now,
        "exp": now + REFRESH_TTL,
    }
    new_refresh_token = sign_jwt(new_refresh_claims, ttl=REFRESH_TTL)

    # Create new access token
    access_jti = _new_jti()
    access_claims = {
        "sub": subject,
        "jti": access_jti,
        "typ": "access",
        "scope": scope,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TTL,
    }
    access_token = sign_jwt(access_claims, ttl=ACCESS_TTL)

    # Persist rotation mapping old_jti -> new_jti and mark old_jti used
    try:
        if old_jti:
            mark_jti_rotated(old_jti, new_refresh_jti)
            mark_jti_used(old_jti)
    except Exception as e:
        write_log({"event": "mark_rotation_error", "error": str(e), "old_jti": old_jti, "new_jti": new_refresh_jti})

    write_log({
        "event": "rotate_refresh_token",
        "sub": subject,
        "old_jti": old_jti,
        "new_jti": new_refresh_jti,
        "chain_id": chain_id,
        "chain_issued_at": chain_issued_at
    }, stream=role or "system")

    return access_token, new_refresh_token, new_refresh_claims

# Public flow that validates and rotates refresh token
def refresh_token_flow(refresh_token: str, requester_payload: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    # Use centralized decode to verify expiry and typ before checks
    payload = decode_token(refresh_token, verify_exp=True, expected_typ="refresh")
    if not payload:
        write_log({"event": "refresh_attempt_invalid_or_expired", "token_snippet": (refresh_token or "")[:48]})
        raise ValueError("refresh_token_invalid_or_expired")

    jti = payload.get("jti")
    chain_id = payload.get("chain_id")
    subject = payload.get("sub")

    # Atomic one-time-use check: attempt to consume jti atomically
    try:
        from server.api.utils.revocation import is_revoked as rev_is_revoked

        if rev_is_revoked(jti):
            write_log({"event": "refresh_attempt_revoked", "jti": jti, "sub": subject})
            raise ValueError("refresh_token_revoked")

        consumed = consume_jti_atomically(jti)
        if not consumed:
            write_log({"event": "refresh_attempt_reuse_or_race", "jti": jti, "sub": subject})
            try:
                revocation_revoke_chain(jti, initiator={"role": "system", "reason": "replay_or_race_detected"})
            except Exception as e:
                write_log({"event": "revoke_chain_on_reuse_error", "error": str(e), "jti": jti})
            raise ValueError("refresh_token_reuse_detected")
    except ValueError:
        raise
    except Exception as e:
        write_log({"event": "revocation_check_error", "error": str(e), "jti": jti})
        raise ValueError("revocation_backend_error")

    # Proceed to rotate; rotate_refresh_token_and_issue_pair will enforce chain TTL and produce new tokens
    access_token, new_refresh_token, _ = rotate_refresh_token_and_issue_pair(refresh_token, requester_payload=requester_payload)

    return access_token, new_refresh_token

# Backwards-compat helper to expose has_scope used by permissions module
def has_scope(payload: Dict[str, Any], required_scope: Optional[str]) -> bool:
    if not required_scope:
        return True
    if not payload:
        return False
    scopes = payload.get("scope", "")
    if isinstance(scopes, str):
        scopes_set = set(scopes.split())
    else:
        scopes_set = set(scopes)
    return required_scope in scopes_set
