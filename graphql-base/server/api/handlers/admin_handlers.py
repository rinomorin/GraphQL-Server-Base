# server/api/handlers/admin_handlers.py
from __future__ import annotations
from typing import Optional, Dict, Any

from server.api.auth.token import admin_rotate_key, retire_kid, has_scope
from server.api.utils.logger import write_log

# Helper to extract caller identity from resolver info/context
def _caller_identity(info) -> Dict[str, Any]:
    ctx = getattr(info, "context", {}) or {}
    auth = ctx.get("auth") or {}
    return {
        "sub": auth.get("sub"),
        "role": auth.get("role"),
        "scopes": auth.get("scope"),
        "ip": ctx.get("remote_addr") or ctx.get("ip"),
    }

def _ensure_admin(info):
    caller = _caller_identity(info)
    role = caller.get("role")
    scopes = caller.get("scopes")
    if role == "admin":
        return True
    if has_scope({"scope": scopes}, "admin:keys"):
        return True
    write_log({"event": "admin_action_denied", "caller": caller})
    raise PermissionError("admin privileges required")

def resolve_admin_rotate_key(obj, info, newKid: str, newKeyMaterial: str, makePreferred: Optional[bool] = True) -> bool:
    _ensure_admin(info)
    caller = _caller_identity(info)
    ok = False
    try:
        ok = admin_rotate_key(newKid, newKeyMaterial, make_preferred=bool(makePreferred))
        # Avoid logging raw key material; do not include newKeyMaterial in logs
        write_log({"event": "admin_rotate_key_called", "caller": caller, "new_kid": newKid, "result": bool(ok)})
    except Exception as e:
        write_log({"event": "admin_rotate_key_error", "caller": caller, "new_kid": newKid, "error": str(e)})
        raise
    return bool(ok)

def resolve_retire_kid(obj, info, kid: str) -> bool:
    _ensure_admin(info)
    caller = _caller_identity(info)
    ok = False
    try:
        ok = retire_kid(kid)
        write_log({"event": "retire_kid_called", "caller": caller, "kid": kid, "result": bool(ok)})
    except Exception as e:
        write_log({"event": "retire_kid_error", "caller": caller, "kid": kid, "error": str(e)})
        raise
    return bool(ok)

# Backwards-compatibility shim expected by routes.py
def resolve_admin_only(obj, info, *args, **kwargs):
    """
    Compatibility shim: routes.py expected resolve_admin_only to be exported.
    If invoked, route to resolve_admin_rotate_key when newKid present,
    otherwise to resolve_retire_kid when 'kid' present.
    This lets older resolver registration continue to work until you update routes.py.
    """
    # Minimal routing based on provided kwargs
    if "newKid" in kwargs or "newKid" in kwargs or "newKid" in kwargs:
        # map GraphQL naming variants to our resolver signature
        newKid = kwargs.get("newKid") or kwargs.get("new_kid")
        newKeyMaterial = kwargs.get("newKeyMaterial") or kwargs.get("new_key_material") or ""
        makePreferred = kwargs.get("makePreferred", True)
        return resolve_admin_rotate_key(obj, info, newKid, newKeyMaterial, makePreferred)
    if "kid" in kwargs or "kid" in kwargs:
        kid = kwargs.get("kid")
        return resolve_retire_kid(obj, info, kid)
    # If called without recognized args, deny
    write_log({"event": "resolve_admin_only_called_invalid", "args": args, "kwargs": kwargs})
    raise PermissionError("invalid admin mutation call")
