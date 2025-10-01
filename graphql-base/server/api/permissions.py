from datetime import datetime, timezone
from server.api.auth.token import has_scope
from server.api.utils.logger import write_log

# Mutation scope mapping used by require_mutation_scope
mutation_scope_map = {
    "login": None,
    "refreshToken": "user:refresh",
    "logout": "user:logout",
    "me": "read:profile",
    "revokeToken": "admin:revoke",
    "adminOnly": "admin:access",
    "revokeRotationChain": "admin:revoke",
    "introspectToken": "admin:introspect"
}

# TTLs for mutations (used by token issuance or audit)
def get_mutation_ttl(mutation_name: str) -> int:
    ttl_map = {
        "login": 3600,
        "refreshToken": 1800,
        "adminOnly": 900,
        "revokeToken": 600,
        "revokeRotationChain": 600,
        "introspectToken": 600
    }
    return ttl_map.get(mutation_name, 3600)

def require_scope(payload: dict, required_scope: str) -> bool:
    if not required_scope:
        return True
    if not has_scope(payload, required_scope):
        write_log({
            "event": "access_denied",
            "reason": f"missing scope: {required_scope}",
            "user_id": payload.get("sub"),
            "trace_id": payload.get("trace_id")
        })
        return False
    return True

def require_mutation_scope(payload: dict, mutation_name: str) -> bool:
    required_scope = mutation_scope_map.get(mutation_name)
    if not required_scope:
        return True
    scopes = payload.get("scope", "")
    if isinstance(scopes, str):
        scopes_set = set(scopes.split())
    else:
        scopes_set = set(scopes)
    if required_scope not in scopes_set:
        write_log({
            "event": "scope_denied",
            "mutation": mutation_name,
            "required_scope": required_scope,
            "user_id": payload.get("sub"),
            "role": payload.get("role"),
            "trace_id": payload.get("trace_id")
        }, stream=payload.get("role", "default"))
        return False
    return True

def require_role(payload: dict, allowed_roles) -> bool:
    role = payload.get("role")
    if role not in allowed_roles:
        write_log({
            "event": "access_denied",
            "reason": f"role '{role}' not allowed",
            "user_id": payload.get("sub"),
            "trace_id": payload.get("trace_id")
        })
        return False
    return True

def allow_mutation(payload: dict, mutation_name: str) -> bool:
    role = payload.get("role")
    allowed = {
        "user": {"login", "refreshToken", "logout", "me"},
        "admin": {"login", "refreshToken", "logout", "me", "revokeToken", "adminOnly", "revokeRotationChain", "introspectToken"},
        "security": {"login", "refreshToken", "logout", "me", "revokeToken"}
    }
    if mutation_name not in allowed.get(role, set()):
        write_log({
            "event": "mutation_denied",
            "mutation": mutation_name,
            "role": role,
            "user_id": payload.get("sub"),
            "trace_id": payload.get("trace_id")
        })
        return False
    return True

def log_mutation(payload, mutation_name: str, status: str, reason: str = None):
    role = payload.get("role", "unknown") if isinstance(payload, dict) else "unknown"
    entry = {
        "event": "mutation_audit",
        "mutation": mutation_name,
        "user_id": payload.get("sub") if isinstance(payload, dict) else None,
        "role": role,
        "trace_id": payload.get("trace_id") if isinstance(payload, dict) else None,
        "status": status,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    write_log(entry, stream=role)
