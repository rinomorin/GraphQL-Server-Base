# server/api/auth/token.py
"""
Token utilities with operational controls:
- Enforce audience and typ claims
- Canonicalize and validate scopes strictly
- Accept tokens signed by preferred kid and also by allowed (retired) kids
- Emit structured audit/metric events via write_log
- Provide helpers for admin-triggered key rotation and retired-key acceptance window
- GC helper for chain metadata file cleanup (fallback)
Exports:
- decode_token, sign_jwt, create_token_pair,
- rotate_refresh_token_and_issue_pair, refresh_token_flow, has_scope,
- admin_rotate_key, retire_kid, gc_chain_meta_files
"""
from __future__ import annotations
import os
import time
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List, Set

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
    is_revoked,
)
from server.api.utils.revocation import revoke_rotation_chain_atomic as revocation_revoke_chain
from server.api.utils.keys import get_key_manager
from server.api.utils.keys_kms import get_secret_from_kms
from pathlib import Path

# Configuration
ENV = os.environ.get("ENV", "dev")
LEGACY_SECRET = os.environ.get("SECRET_KEY", "changeme-local-dev")
ALGORITHM = os.environ.get("JWT_ALG", "HS256")
REQUIRED_AUD = os.environ.get("JWT_AUD", "")  # expected audience for all issued tokens; empty => not enforced
ACCESS_TTL = int(os.environ.get("ACCESS_TTL", 300))
REFRESH_TTL = int(os.environ.get("REFRESH_TTL", 60 * 60 * 24))
MAX_CHAIN_LIFETIME_SECONDS = int(os.environ.get("MAX_CHAIN_LIFETIME_SECONDS", 7 * 24 * 3600))
CHAIN_METADATA_TTL = MAX_CHAIN_LIFETIME_SECONDS + 3600
ENFORCE_CHAIN_TTL = os.environ.get("ENFORCE_CHAIN_TTL", "1") == "1"

# KeyManager and retired kids store
_key_manager = get_key_manager()
# Permitted non-preferred kids (retired) for verification; stored as set of kid strings
# KeyManager persistence layer can also store retired keys; here we use runtime set and KeyManager.list_keys()
_retired_kids: Set[str] = set()
# Window (seconds) tokens signed by retired kids are accepted; 0 means indefinite until retired key removed
RETIRED_KID_ACCEPT_WINDOW = int(os.environ.get("RETIRED_KID_ACCEPT_WINDOW", 0))

# Safety checks
if ENV != "dev":
    if not _key_manager.list_keys() and LEGACY_SECRET == "changeme-local-dev":
        raise RuntimeError("insecure default SECRET_KEY in non-dev; configure signing keys")

# Helpers
def _new_jti() -> str:
    return str(uuid.uuid4())

def _now() -> int:
    return int(time.time())

def _canonicalize_scopes(scopes: Optional[Any]) -> str:
    """
    Canonicalize scopes into a stable space-separated string.
    Accepts list/tuple/set or space/comma-separated string.
    """
    if not scopes:
        return ""
    if isinstance(scopes, (list, tuple, set)):
        parts = [str(s).strip() for s in scopes if s and str(s).strip()]
    else:
        # split on whitespace or commas
        raw = str(scopes)
        parts = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
    # dedupe while preserving order: use dict.fromkeys
    seen = dict.fromkeys(parts)
    return " ".join(seen.keys())

def _resolve_key(kid: Optional[str]) -> str:
    # prefer KeyManager cached keys
    key = _key_manager.get_key(kid)
    if key:
        return key
    # fallback to KMS adapter
    try:
        kms_secret = get_secret_from_kms(kid) if kid else None
        if kms_secret:
            try:
                _key_manager.add_key(kid, kms_secret, make_preferred=False)
            except Exception:
                pass
            return kms_secret
    except Exception:
        pass
    return LEGACY_SECRET

def _verify_with_allowed_kids(token: str, header_kid: Optional[str], verify_exp: bool) -> Optional[Dict[str, Any]]:
    """
    Attempt verification using:
     1) key resolved from header_kid (preferred or specified)
     2) if that fails, try other available keys in KeyManager (retired or previous kids)
    Emits metric if token verified by non-preferred kid.
    Returns payload dict on success, None on failure.
    """
    # try header kid / resolved key first
    key = _resolve_key(header_kid)
    options = {"verify_exp": verify_exp}
    try:
        payload = jwt.decode(token, key, algorithms=[ALGORITHM], options=options)
        # record verification metric
        preferred = _key_manager.get_preferred() if hasattr(_key_manager, "get_preferred") else None
        if header_kid and preferred and header_kid != preferred:
            write_log({"event": "token_verified_by_non_preferred_kid", "kid": header_kid, "preferred": preferred, "jti": payload.get("jti")})
        else:
            write_log({"event": "token_verified", "kid": header_kid or "legacy", "jti": payload.get("jti")})
        return payload
    except ExpiredSignatureError:
        write_log({"event": "token_expired", "token_snippet": (token or "")[:48], "kid": header_kid})
        return None
    except JWTError:
        # try other keys known to KeyManager (retired previous keys)
        keys = _key_manager.list_keys() or {}
        for k in keys.keys():
            # skip header kid (already tried)
            if k == header_kid:
                continue
            try:
                candidate_key = _resolve_key(k)
                payload = jwt.decode(token, candidate_key, algorithms=[ALGORITHM], options=options)
                write_log({"event": "token_verified_by_non_header_kid", "verified_kid": k, "header_kid": header_kid, "jti": payload.get("jti")})
                return payload
            except Exception:
                continue
        # final fallback: legacy secret
        try:
            payload = jwt.decode(token, LEGACY_SECRET, algorithms=[ALGORITHM], options=options)
            write_log({"event": "token_verified_by_legacy_secret", "jti": payload.get("jti")})
            return payload
        except Exception:
            write_log({"event": "token_decode_failed", "token_snippet": (token or "")[:48], "header_kid": header_kid})
            return None
    except Exception as e:
        write_log({"event": "token_decode_unexpected", "error": str(e), "token_snippet": (token or "")[:48], "kid": header_kid})
        return None

# Centralized decode helper with aud and typ enforcement
def decode_token(token: str, verify_exp: bool = True, expected_typ: Optional[str] = None, expected_aud: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        write_log({"event": "jwt_header_parse_error", "error": str(e), "token_snippet": (token or "")[:48]})
        return None

    kid = header.get("kid")
    payload = _verify_with_allowed_kids(token, kid, verify_exp)
    if not payload:
        return None

    # enforce typ
    if expected_typ:
        typ = payload.get("typ")
        if typ != expected_typ:
            write_log({"event": "token_typ_mismatch", "expected": expected_typ, "actual": typ, "token_jti": payload.get("jti")})
            return None

    # enforce audience if configured or requested
    aud_to_check = expected_aud or REQUIRED_AUD or None
    if aud_to_check:
        aud_claim = payload.get("aud")
        if not aud_claim:
            write_log({"event": "token_missing_aud", "required_aud": aud_to_check, "jti": payload.get("jti")})
            return None
        # aud may be string or list
        if isinstance(aud_claim, list):
            if aud_to_check not in aud_claim:
                write_log({"event": "token_aud_mismatch", "required_aud": aud_to_check, "actual_aud": aud_claim, "jti": payload.get("jti")})
                return None
        else:
            if str(aud_claim) != str(aud_to_check):
                write_log({"event": "token_aud_mismatch", "required_aud": aud_to_check, "actual_aud": aud_claim, "jti": payload.get("jti")})
                return None

    return payload

# Signing helper with aud and canonical scope
def sign_jwt(claims: Dict[str, Any], ttl: Optional[int] = None, kid: Optional[str] = None, aud: Optional[str] = None) -> str:
    payload = dict(claims)
    now = _now()
    payload.setdefault("iat", now)
    if ttl is not None:
        payload["exp"] = now + int(ttl)
    elif "exp" not in payload:
        payload["exp"] = now + ACCESS_TTL

    # canonicalize scope
    if "scope" in payload:
        payload["scope"] = _canonicalize_scopes(payload.get("scope"))
    else:
        payload["scope"] = ""

    # attach audience if provided or required
    if aud:
        payload["aud"] = aud
    elif REQUIRED_AUD:
        payload["aud"] = REQUIRED_AUD

    chosen_kid = kid or (_key_manager.get_preferred() if hasattr(_key_manager, "get_preferred") else None)
    key = _resolve_key(chosen_kid) or LEGACY_SECRET
    headers = {}
    if chosen_kid:
        headers["kid"] = chosen_kid

    token = jwt.encode(payload, key, algorithm=ALGORITHM, headers=headers)
    write_log({"event": "token_issued", "typ": payload.get("typ"), "aud": payload.get("aud"), "jti": payload.get("jti")})
    return token

# High-level token pair creator
def create_token_pair(subject: str, scope: str = "", role: Optional[str] = None, aud: Optional[str] = None) -> Tuple[str, str, Dict[str, Any]]:
    now = _now()
    access_jti = _new_jti()
    access_claims = {
        "sub": subject,
        "jti": access_jti,
        "typ": "access",
        "scope": _canonicalize_scopes(scope),
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TTL,
    }
    access_token = sign_jwt(access_claims, ttl=ACCESS_TTL, aud=aud)

    refresh_jti = _new_jti()
    chain_id = str(uuid.uuid4())
    chain_issued_at = now

    refresh_claims = {
        "sub": subject,
        "jti": refresh_jti,
        "typ": "refresh",
        "scope": _canonicalize_scopes(scope),
        "role": role,
        "chain_id": chain_id,
        "chain_issued_at": chain_issued_at,
        "iat": now,
        "exp": now + REFRESH_TTL,
    }
    refresh_token = sign_jwt(refresh_claims, ttl=REFRESH_TTL, aud=aud)

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

# Rotation / refresh logic (unchanged semantics; uses decode_token/sign_jwt)
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

    # Server-authoritative chain meta check
    meta = None
    if chain_id:
        meta = get_chain_meta(chain_id)
        if not meta:
            write_log({"event": "chain_meta_missing_or_invalid", "chain_id": chain_id, "jti": old_jti})
            try:
                revocation_revoke_chain(old_jti, initiator={"role": "system", "reason": "chain_meta_invalid"})
            except Exception:
                pass
            raise ValueError("refresh_denied_chain_meta_invalid")
        try:
            chain_issued_at = int(meta.get("chain_issued_at"))
        except Exception:
            pass

    # Enforce chain TTL
    if ENFORCE_CHAIN_TTL:
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
                    origin_jti = meta.get("origin_jti") if meta else None
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
        "scope": _canonicalize_scopes(scope),
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
        "scope": _canonicalize_scopes(scope),
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

# Public refresh flow
def refresh_token_flow(refresh_token: str, requester_payload: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    payload = decode_token(refresh_token, verify_exp=True, expected_typ="refresh")
    if not payload:
        write_log({"event": "refresh_attempt_invalid_or_expired", "token_snippet": (refresh_token or "")[:48]})
        raise ValueError("refresh_token_invalid_or_expired")

    jti = payload.get("jti")
    chain_id = payload.get("chain_id")
    subject = payload.get("sub")

    # Revoked check
    try:
        if is_revoked(jti):
            write_log({"event": "refresh_attempt_revoked", "jti": jti, "sub": subject})
            raise ValueError("refresh_token_revoked")
    except Exception as e:
        write_log({"event": "revocation_check_error", "error": str(e), "jti": jti})
        raise ValueError("revocation_backend_error")

    # Atomic one-time-use consume
    try:
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

    # Proceed to rotation
    access_token, new_refresh_token, _ = rotate_refresh_token_and_issue_pair(refresh_token, requester_payload=requester_payload)
    return access_token, new_refresh_token

# Scope helper
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

# -------------------- Operational helpers --------------------
def admin_rotate_key(new_kid: str, new_key_material: str, make_preferred: bool = True) -> bool:
    """
    Admin API helper: add a new key and optionally make it preferred.
    Should be exposed via an admin-only mutation or endpoint with strict RBAC and audit logging.
    """
    try:
        _key_manager.add_key(new_kid, new_key_material, make_preferred=make_preferred)
        write_log({"event": "admin_rotate_key", "new_kid": new_kid, "make_preferred": make_preferred})
        return True
    except Exception as e:
        write_log({"event": "admin_rotate_key_error", "error": str(e), "new_kid": new_kid})
        return False

def retire_kid(kid: str) -> bool:
    """
    Mark a kid as retired (allowed for verification for a window) and remove it from preferred rotation.
    The actual removal from KeyManager should be a separate admin operation after acceptance window.
    """
    try:
        _retired_kids.add(kid)
        write_log({"event": "retire_kid", "kid": kid})
        # don't delete from KeyManager right away; operations can call retire_kid and later remove
        return True
    except Exception as e:
        write_log({"event": "retire_kid_error", "error": str(e), "kid": kid})
        return False

def gc_chain_meta_files(max_age_seconds: int = 30 * 24 * 3600) -> int:
    """
    Garbage-collect local chain meta files older than max_age_seconds.
    Returns number of files removed.
    Useful for local dev to avoid accumulating .chain_meta_*.json files.
    """
    removed = 0
    root = Path(__file__).resolve().parents[2]
    for f in root.glob(".chain_meta_*.json"):
        try:
            mtime = f.stat().st_mtime
            if (time.time() - mtime) > max_age_seconds:
                f.unlink()
                removed += 1
        except Exception:
            continue
    write_log({"event": "gc_chain_meta_files", "removed": removed})
    return removed
