# server/api/utils/logger.py
import json
import time
from datetime import datetime, timezone
from typing import List, Optional, Any
import os

# Optional direct redis use for helpers; keep lazy import to avoid hard dependency
_redis_client = None
REDIS_URL = os.environ.get("REDIS_URL", "")

def get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not REDIS_URL:
        return None
    try:
        import redis
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        # quick connection test
        _redis_client.ping()
        return _redis_client
    except Exception:
        _redis_client = None
        return None

# Re-export revocation wrapper API if available, otherwise provide simple local fallbacks
try:
    from server.api.utils.revocation import (
        mark_jti_rotated as rev_mark_jti_rotated,
        is_jti_rotated as rev_is_jti_rotated,
        mark_jti_used as rev_mark_jti_used,
        is_jti_used as rev_is_jti_used,
        add_revoked as rev_add_revoked,
        is_revoked as rev_is_revoked,
        get_next_rotated as rev_get_next_rotated,
        collect_lineage as rev_collect_lineage,
        revoke_rotation_chain_atomic as rev_revoke_rotation_chain_atomic,
    )
except Exception:
    # No revocation wrapper available; define minimal fallbacks that are no-ops or conservative
    rev_mark_jti_rotated = lambda old, new: False
    rev_is_jti_rotated = lambda jti: False
    rev_mark_jti_used = lambda jti: False
    rev_is_jti_used = lambda jti: False
    rev_add_revoked = lambda jti: False
    rev_is_revoked = lambda jti: False
    rev_get_next_rotated = lambda jti: None
    rev_collect_lineage = lambda jti: []
    def rev_revoke_rotation_chain_atomic(start_jti: str, initiator: Optional[dict] = None, lock_timeout: int = 10) -> List[str]:
        return []

# Basic structured logging function
def write_log(entry: dict, stream: str = "default"):
    entry = dict(entry)
    entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    entry.setdefault("stream", stream)
    print(json.dumps(entry, ensure_ascii=False))

# TTL expiry logging
def log_ttl_expiry(jti: str, reason: str = "expired", initiator: Optional[dict] = None) -> bool:
    if not jti:
        return False
    entry = {
        "event": "ttl_expiry",
        "jti": jti,
        "reason": reason,
        "initiator": initiator or {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    write_log(entry, stream=(initiator.get("role") if isinstance(initiator, dict) else "system"))
    return True

# Thin wrappers over revocation API to preserve earlier function names used across the codebase
def mark_jti_rotated(old_jti: str, new_jti: str) -> bool:
    return rev_mark_jti_rotated(old_jti, new_jti)

def is_jti_rotated(jti: str) -> bool:
    return rev_is_jti_rotated(jti)

def mark_jti_used(jti: str) -> bool:
    return rev_mark_jti_used(jti)

def is_jti_used(jti: str) -> bool:
    return rev_is_jti_used(jti)

def add_revoked(jti: str) -> bool:
    return rev_add_revoked(jti)

def is_revoked(jti_or_token: str) -> bool:
    """
    Prefer callers to pass a raw jti. If a full token string is provided,
    callers should extract jti before calling this function.
    """
    if not jti_or_token:
        return False
    try:
        return bool(rev_is_revoked(jti_or_token))
    except Exception:
        write_log({"event": "is_revoked_error", "jti_or_token": jti_or_token})
        return False

def get_next_rotated(jti: str) -> Optional[str]:
    try:
        return rev_get_next_rotated(jti)
    except Exception:
        return None

def collect_lineage(start_jti: str) -> List[str]:
    try:
        return rev_collect_lineage(start_jti)
    except Exception:
        return []

def revoke_rotation_chain_atomic(start_jti: str, initiator: Optional[dict] = None, lock_timeout: int = 10) -> List[str]:
    """
    Delegate to revocation implementation which may use Redis for atomic locking.
    Returns list of revoked JTIs.
    """
    return rev_revoke_rotation_chain_atomic(start_jti, initiator, lock_timeout)

# Revoke a token (blacklist / forensic audit). Prefer JTI when available.
def revoke_token(token_str: str, jti: str = None, initiator: Optional[dict] = None) -> bool:
    """
    Revoke a token for application-level blacklisting.
    - token_str: optional full token string (used for logging/diagnostics)
    - jti: preferred identifier to mark revoked (if available)
    - initiator: optional dict with caller metadata for audit logging

    Behavior:
    - If a revocation backend is available (rev_add_revoked), mark the jti revoked.
    - Always emit a structured audit event via write_log.
    - Return True on success (best-effort), False on obvious failure.
    """
    try:
        payload_info = initiator or {}
        snippet = (token_str or "")[:48]
        ok = False
        if jti:
            try:
                ok = bool(rev_add_revoked(jti))
            except Exception:
                ok = False

        # Also mark as used if we have a jti to avoid reuse
        if jti:
            try:
                rev_mark_jti_used(jti)
            except Exception:
                pass

        write_log({
            "event": "revoke_token",
            "token_snippet": snippet,
            "jti": jti,
            "initiator": payload_info,
            "success": bool(ok),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, stream=(payload_info.get("role") if isinstance(payload_info, dict) else "system"))

        return bool(ok)
    except Exception as e:
        write_log({
            "event": "revoke_token_error",
            "error": str(e),
            "token_snippet": (token_str or "")[:48],
            "jti": jti,
            "initiator": initiator or {}
        })
        return False
