# server/api/utils/revocation.py
"""
Revocation wrapper with Redis primary store, Lua atomic consume, HMAC-signed chain metadata,
and file fallback for single-node/dev deployments.

Public API:
- mark_jti_rotated(old_jti, new_jti)
- is_jti_rotated(jti)
- get_next_rotated(jti)
- collect_lineage(start_jti)
- mark_jti_used(jti)
- is_jti_used(jti)
- add_revoked(jti)
- is_revoked(jti)
- acquire_consume_lock(jti), release_consume_lock(jti)
- consume_jti_atomically(jti)
- create_chain_meta(chain_id, origin_jti, chain_issued_at, ttl)
- get_chain_meta(chain_id)
- set_chain_revoked(chain_id)
- revoke_rotation_chain_atomic(start_jti, initiator=None, lock_timeout=10)
- migrate_files_to_redis()
"""
from __future__ import annotations
import os
import json
import threading
import time
import hmac
import hashlib
from typing import List, Optional, Dict
from pathlib import Path

REDIS_URL = os.environ.get("REDIS_URL", "")
USE_REDIS = bool(REDIS_URL)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
FALLBACK_REVOKED_FILE = _PROJECT_ROOT / ".revoked_jtis.txt"
FALLBACK_USED_FILE = _PROJECT_ROOT / ".used_jtis.txt"
FALLBACK_ROTATED_FILE = _PROJECT_ROOT / ".rotated_map.json"

# Lazy redis import to avoid hard dependency during fallback/dev
_redis_client = None
_redis_lock = threading.Lock()

# Redis keys
ROTATED_MAP_KEY = "jti:rotated_map"
REVOKED_SET_KEY = "jti:revoked_set"
USED_SET_KEY = "jti:used_set"

# Consume lock / audit
CONSUME_LOCK_KEY_PREFIX = "jti:consume_lock:"
CONSUME_LOCK_TTL = 10  # seconds
AUDIT_LIST_PREFIX = "jti:consume_audit:"

# Chain metadata HMAC key (must be set in prod)
REVOCATION_HMAC_KEY = os.environ.get("REVOCATION_HMAC_KEY", "")

# Embedded Lua script for atomic consume + audit
_CONSUME_LUA = """
local jti = ARGV[1]
local now = ARGV[2]
local audit_entry = ARGV[3]
local used_key = KEYS[1]
local revoked_key = KEYS[2]
local audit_list = KEYS[3]
-- check revoked
if redis.call("SISMEMBER", revoked_key, jti) == 1 then
  return -1
end
-- check used
if redis.call("SISMEMBER", used_key, jti) == 1 then
  return 0
end
-- mark used
redis.call("SADD", used_key, jti)
-- push audit entry
redis.call("LPUSH", audit_list, audit_entry)
return 1
"""
_consume_lua_sha = None

def _init_redis():
    global _redis_client
    if not USE_REDIS:
        return None
    if _redis_client is not None:
        return _redis_client
    try:
        import redis
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        _redis_client.ping()
        # register lua script
        _register_consume_lua(_redis_client)
        return _redis_client
    except Exception:
        _redis_client = None
        return None

def _use_redis():
    return _init_redis()

def _register_consume_lua(r):
    global _consume_lua_sha
    try:
        _consume_lua_sha = r.script_load(_CONSUME_LUA)
    except Exception:
        _consume_lua_sha = None

def _ensure_files():
    FALLBACK_REVOKED_FILE.parent.mkdir(parents=True, exist_ok=True)
    for p in (FALLBACK_REVOKED_FILE, FALLBACK_USED_FILE, FALLBACK_ROTATED_FILE):
        if not p.exists():
            if p.suffix == ".json":
                p.write_text(json.dumps({}), encoding="utf-8")
            else:
                p.write_text("", encoding="utf-8")

# ---------- File helpers ----------
def _read_set_file(path: Path) -> set:
    try:
        if not path.exists():
            return set()
        with path.open("r", encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        return set(lines)
    except Exception:
        return set()

def _append_set_file(path: Path, value: str):
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(value + "\n")
    except Exception:
        pass

def _read_json_file(path: Path) -> Dict[str, str]:
    try:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}

def _write_json_file(path: Path, obj: Dict[str, str]):
    try:
        path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

# ---------- HMAC helpers for chain metadata ----------
def _hmac_sign(data: str) -> str:
    if not REVOCATION_HMAC_KEY:
        return ""
    try:
        return hmac.new(REVOCATION_HMAC_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()
    except Exception:
        return ""

def _hmac_verify(data: str, signature: str) -> bool:
    if not signature or not REVOCATION_HMAC_KEY:
        return False
    try:
        expected = _hmac_sign(data)
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False

# ---------- Public API (Redis or file) ----------
def mark_jti_rotated(old_jti: str, new_jti: str) -> bool:
    if not old_jti or not new_jti:
        return False
    r = _use_redis()
    if r:
        try:
            r.hset(ROTATED_MAP_KEY, old_jti, new_jti)
            return True
        except Exception:
            pass
    _ensure_files()
    mapping = _read_json_file(FALLBACK_ROTATED_FILE)
    mapping[old_jti] = new_jti
    _write_json_file(FALLBACK_ROTATED_FILE, mapping)
    return True

def is_jti_rotated(jti: str) -> bool:
    if not jti:
        return False
    r = _use_redis()
    if r:
        try:
            return bool(r.hexists(ROTATED_MAP_KEY, jti))
        except Exception:
            pass
    _ensure_files()
    mapping = _read_json_file(FALLBACK_ROTATED_FILE)
    return jti in mapping

def get_next_rotated(jti: str) -> Optional[str]:
    if not jti:
        return None
    r = _use_redis()
    if r:
        try:
            return r.hget(ROTATED_MAP_KEY, jti)
        except Exception:
            pass
    _ensure_files()
    mapping = _read_json_file(FALLBACK_ROTATED_FILE)
    return mapping.get(jti)

def collect_lineage(start_jti: str) -> List[str]:
    if not start_jti:
        return []
    r = _use_redis()
    lineage = []
    seen = set()
    current = start_jti
    while True:
        next_jti = None
        if r:
            try:
                next_jti = r.hget(ROTATED_MAP_KEY, current)
            except Exception:
                next_jti = None
        else:
            _ensure_files()
            mapping = _read_json_file(FALLBACK_ROTATED_FILE)
            next_jti = mapping.get(current)
        if not next_jti:
            break
        if next_jti in seen:
            break
        seen.add(next_jti)
        lineage.append(next_jti)
        current = next_jti
    return lineage

def mark_jti_used(jti: str) -> bool:
    if not jti:
        return False
    r = _use_redis()
    if r:
        try:
            r.sadd(USED_SET_KEY, jti)
            return True
        except Exception:
            pass
    _ensure_files()
    _append_set_file(FALLBACK_USED_FILE, jti)
    return True

def is_jti_used(jti: str) -> bool:
    if not jti:
        return False
    r = _use_redis()
    if r:
        try:
            return bool(r.sismember(USED_SET_KEY, jti))
        except Exception:
            pass
    _ensure_files()
    s = _read_set_file(FALLBACK_USED_FILE)
    return jti in s

def add_revoked(jti: str) -> bool:
    if not jti:
        return False
    r = _use_redis()
    if r:
        try:
            r.sadd(REVOKED_SET_KEY, jti)
            return True
        except Exception:
            pass
    _ensure_files()
    _append_set_file(FALLBACK_REVOKED_FILE, jti)
    return True

def is_revoked(jti: str) -> bool:
    if not jti:
        return False
    r = _use_redis()
    if r:
        try:
            return bool(r.sismember(REVOKED_SET_KEY, jti))
        except Exception:
            pass
    _ensure_files()
    s = _read_set_file(FALLBACK_REVOKED_FILE)
    return jti in s

# ---------- Consume lock and atomic consume helpers ----------
def _acquire_file_consume_lock(jti: str, ttl: int = CONSUME_LOCK_TTL) -> bool:
    lock_file = _PROJECT_ROOT / f".consume_{jti}.lock"
    now = int(time.time())
    try:
        if lock_file.exists():
            try:
                data = json.loads(lock_file.read_text(encoding="utf-8") or "{}")
                ts = int(data.get("ts", 0))
            except Exception:
                ts = 0
            if now - ts < ttl:
                return False
        lock_file.write_text(json.dumps({"ts": now}), encoding="utf-8")
        return True
    except Exception:
        return False

def _release_file_consume_lock(jti: str):
    lock_file = _PROJECT_ROOT / f".consume_{jti}.lock"
    try:
        if lock_file.exists():
            lock_file.unlink()
    except Exception:
        pass

def acquire_consume_lock(jti: str, ttl: int = CONSUME_LOCK_TTL) -> bool:
    if not jti:
        return False
    r = _use_redis()
    key = CONSUME_LOCK_KEY_PREFIX + jti
    if r:
        try:
            return bool(r.set(name=key, value="1", nx=True, ex=ttl))
        except Exception:
            pass
    return _acquire_file_consume_lock(jti, ttl)

def release_consume_lock(jti: str):
    if not jti:
        return
    r = _use_redis()
    key = CONSUME_LOCK_KEY_PREFIX + jti
    if r:
        try:
            r.delete(key)
            return
        except Exception:
            pass
    _release_file_consume_lock(jti)

def consume_jti_atomically(jti: str, lock_ttl: int = CONSUME_LOCK_TTL) -> bool:
    """
    Redis path: call embedded Lua script to atomically:
      - check revoked set
      - check used set
      - add to used set
      - LPUSH an audit entry into a sharded audit list
    Returns True on success (first consumer), False if already used, raises nothing.
    If Redis unavailable, best-effort file fallback is used.
    """
    if not jti:
        return False
    r = _use_redis()
    if r:
        try:
            if _consume_lua_sha is None:
                _register_consume_lua(r)
            audit_entry = json.dumps({"event": "consume_attempt", "jti": jti, "ts": int(time.time())}, ensure_ascii=False)
            audit_list_key = AUDIT_LIST_PREFIX + (jti[:8] if jti else "unknown")
            # KEYS: used_key, revoked_key, audit_list
            # ARGV: jti, now, audit_entry
            try:
                res = r.evalsha(_consume_lua_sha, 3, USED_SET_KEY, REVOKED_SET_KEY, audit_list_key, jti, str(int(time.time())), audit_entry)
            except Exception:
                # fallback to eval if evalsha fails (script not loaded)
                res = r.eval(_CONSUME_LUA, 3, USED_SET_KEY, REVOKED_SET_KEY, audit_list_key, jti, str(int(time.time())), audit_entry)
            # res: integer -1 revoked, 0 used, 1 success
            try:
                res_int = int(res)
                return res_int == 1
            except Exception:
                return False
        except Exception:
            pass
    # File-fallback best-effort
    if not _acquire_file_consume_lock(jti, lock_ttl):
        return False
    try:
        s = _read_set_file(FALLBACK_USED_FILE)
        if jti in s:
            return False
        _append_set_file(FALLBACK_USED_FILE, jti)
        # append a simple audit file entry for local dev
        try:
            audit_file = _PROJECT_ROOT / f".consume_audit_{jti[:8]}.log"
            audit_file.write_text(json.dumps({"event": "consume_attempt", "jti": jti, "ts": int(time.time())}, ensure_ascii=False) + "\n", encoding="utf-8")
        except Exception:
            pass
        return True
    finally:
        _release_file_consume_lock(jti)

# ---------- Atomic revoke chain (fallback local) ----------
def revoke_rotation_chain_atomic(start_jti: str, initiator: Optional[dict] = None, lock_timeout: int = 10) -> List[str]:
    """
    Prefer a logger-provided implementation (may use Redis locks) if available.
    This fallback reads the rotated map and marks JTIs revoked/used.
    Returns list of revoked JTIs.
    """
    try:
        from server.api.utils.logger import revoke_rotation_chain_atomic as logger_revoke
        r = _use_redis()
        if r and callable(logger_revoke):
            return logger_revoke(start_jti, initiator, lock_timeout)
    except Exception:
        pass

    _ensure_files()
    mapping = _read_json_file(FALLBACK_ROTATED_FILE)
    revoked = []
    current = start_jti
    seen = set()
    while True:
        next_jti = mapping.get(current)
        if not next_jti:
            break
        if next_jti in seen:
            break
        seen.add(next_jti)
        revoked.append(next_jti)
        current = next_jti

    if not revoked:
        return []

    for j in revoked:
        add_revoked(j)
        mark_jti_used(j)

    print(json.dumps({
        "event": "revoke_rotation_chain_fallback",
        "start_jti": start_jti,
        "revoked_count": len(revoked),
        "revoked": revoked,
        "initiator": initiator or {}
    }, ensure_ascii=False))

    return revoked

# ---------- Chain metadata helpers (Redis primary, file fallback) ----------
def create_chain_meta(chain_id: str, origin_jti: str, chain_issued_at: int, ttl: int):
    """
    Store chain metadata as server-authoritative signed payload.
    Stored object: { "payload": JSON.stringify({chain_issued_at, origin_jti}), "sig": HMAC(payload), "revoked": 0 }
    """
    if not chain_id:
        return False
    r = _use_redis()
    key = f"chain:meta:{chain_id}"
    payload_obj = {"chain_issued_at": int(chain_issued_at), "origin_jti": origin_jti}
    payload = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False)
    sig = _hmac_sign(payload)
    if r:
        try:
            r.hset(key, mapping={"payload": payload, "sig": sig, "revoked": 0})
            r.expire(key, ttl)
            return True
        except Exception:
            pass
    _ensure_files()
    meta_file = _PROJECT_ROOT / f".chain_meta_{chain_id}.json"
    try:
        meta_file.write_text(json.dumps({"payload": payload, "sig": sig, "revoked": 0}, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    return True

def get_chain_meta(chain_id: str):
    """
    Return parsed metadata dict if present and HMAC verifies, otherwise None.
    Parsed dict includes chain_issued_at (int), origin_jti (str), revoked (bool/int)
    """
    if not chain_id:
        return None
    r = _use_redis()
    key = f"chain:meta:{chain_id}"
    if r:
        try:
            if not r.exists(key):
                return None
            data = r.hgetall(key)
            payload = data.get("payload")
            sig = data.get("sig")
            if not payload or not _hmac_verify(payload, sig):
                return None
            parsed = json.loads(payload)
            parsed["revoked"] = data.get("revoked") in ("1", 1, "True", "true")
            return parsed
        except Exception:
            pass
    _ensure_files()
    meta_file = _PROJECT_ROOT / f".chain_meta_{chain_id}.json"
    if meta_file.exists():
        try:
            raw = json.loads(meta_file.read_text(encoding="utf-8") or "{}")
            payload = raw.get("payload")
            sig = raw.get("sig")
            if not payload or not _hmac_verify(payload, sig):
                return None
            parsed = json.loads(payload)
            parsed["revoked"] = raw.get("revoked", 0)
            return parsed
        except Exception:
            return None
    return None

def set_chain_revoked(chain_id: str):
    if not chain_id:
        return False
    r = _use_redis()
    key = f"chain:meta:{chain_id}"
    if r:
        try:
            r.hset(key, "revoked", 1)
            return True
        except Exception:
            pass
    _ensure_files()
    meta_file = _PROJECT_ROOT / f".chain_meta_{chain_id}.json"
    if meta_file.exists():
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
            data["revoked"] = 1
            meta_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            return True
        except Exception:
            pass
    return False

# ---------- Migration helper ----------
def migrate_files_to_redis():
    r = _use_redis()
    if not r:
        raise RuntimeError("Redis not available")
    _ensure_files()
    revoked = _read_set_file(FALLBACK_REVOKED_FILE)
    if revoked:
        r.sadd(REVOKED_SET_KEY, *revoked)
    used = _read_set_file(FALLBACK_USED_FILE)
    if used:
        r.sadd(USED_SET_KEY, *used)
    mapping = _read_json_file(FALLBACK_ROTATED_FILE)
    if mapping:
        pipe = r.pipeline()
        for k, v in mapping.items():
            pipe.hset(ROTATED_MAP_KEY, k, v)
        pipe.execute()
    # migrate chain meta files
    for f in _PROJECT_ROOT.glob(".chain_meta_*.json"):
        try:
            raw = json.loads(f.read_text(encoding="utf-8") or "{}")
            payload = raw.get("payload")
            sig = raw.get("sig")
            if not payload:
                continue
            chain_obj = json.loads(payload)
            chain_id = f.stem.replace(".chain_meta_", "")
            key = f"chain:meta:{chain_id}"
            pipe = r.pipeline()
            pipe.hset(key, "payload", payload)
            pipe.hset(key, "sig", sig or "")
            pipe.hset(key, "revoked", int(raw.get("revoked", 0)))
            pipe.execute()
        except Exception:
            pass
    return True
