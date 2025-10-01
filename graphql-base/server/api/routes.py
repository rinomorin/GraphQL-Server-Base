from ariadne import QueryType, MutationType
from server.api.auth.user import get_user
from server.api.auth.password import verify_password
from server.api.auth.token import create_token_pair, decode_token, has_scope
from server.api.settings import ACCESS_TOKEN_EXPIRE_MINUTES
from server.api.utils.logger import write_log, revoke_token
from datetime import datetime, timedelta, timezone
import uuid

query = QueryType()
mutation = MutationType()

def require_scope(payload, required_scope):
    if not has_scope(payload, required_scope):
        write_log({
            "event": "access_denied",
            "reason": f"missing scope: {required_scope}",
            "user_id": payload.get("sub"),
            "trace_id": payload.get("trace_id")
        })
        return False
    return True

def require_role(payload, allowed_roles):
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

def allow_mutation(payload, mutation_name):
    role = payload.get("role")
    allowed = {
        "user": {"login", "refreshToken", "logout", "me"},
        "admin": {"login", "refreshToken", "logout", "me", "revokeToken", "adminOnly"},
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

def log_mutation(payload, mutation_name, status, reason=None):
    role = payload.get("role", "unknown")
    entry = {
        "event": "mutation_audit",
        "mutation": mutation_name,
        "user_id": payload.get("sub"),
        "role": role,
        "trace_id": payload.get("trace_id"),
        "status": status,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Split logs by role
    write_log(entry, stream=role)

def get_mutation_ttl(mutation_name):
    ttl_map = {
        "login": 3600,
        "refreshToken": 1800,
        "adminOnly": 900,
        "revokeToken": 600
    }
    return ttl_map.get(mutation_name, 3600)

@query.field("ping")
def resolve_ping(_, info):
    return "pong"

@query.field("me")
def resolve_me(_, info):
    token = info.context.get("token")
    if not token:
        return None

    payload = decode_token(token)
    if not payload or not require_scope(payload, "read"):
        return None

    return {
        "user_id": payload["sub"],
        "scope": payload.get("scope", ""),
        "issued_at": payload.get("iat"),
        "trace_id": payload.get("trace_id"),
        "role": payload.get("role")
    }

@mutation.field("login")
def resolve_login(_, info, username, password):
    username = username.strip().lower()
    password = password.strip()

    write_log({"event": "login_attempt", "username": username})

    user = get_user(username)
    if not user:
        log_mutation({}, "login", "denied", "user not found")
        return None

    password_valid = verify_password(password, user["hashed_password"])
    if not password_valid:
        log_mutation({}, "login", "denied", "invalid password")
        return None

    trace_id = str(uuid.uuid4())
    payload = {"sub": user["id"], "role": user.get("role", "user"), "trace_id": trace_id}
    log_mutation(payload, "login", "success")

    ttl = get_mutation_ttl("login")
    return create_token_pair(user["id"], role=user.get("role", "user"), ttl_override=ttl)

@mutation.field("refreshToken")
def resolve_refresh_token(_, info, refresh_token):
    payload = decode_token(refresh_token, expected_type="refresh")
    if not payload:
        log_mutation({}, "refreshToken", "denied", "invalid or expired token")
        return None

    log_mutation(payload, "refreshToken", "success")
    ttl = get_mutation_ttl("refreshToken")
    return create_token_pair(payload["sub"], role=payload.get("role", "user"), ttl_override=ttl)

@mutation.field("logout")
def resolve_logout(_, info):
    token = info.context.get("token")
    if not token:
        log_mutation({}, "logout", "denied", "no token provided")
        return False

    payload = decode_token(token)
    if not payload:
        log_mutation({}, "logout", "denied", "invalid token")
        return False

    log_mutation(payload, "logout", "success")
    return True

@mutation.field("revokeToken")
def resolve_revoke_token(_, info, token: str):
    token_context = info.context.get("token")
    payload = decode_token(token_context)
    if not payload:
        log_mutation({}, "revokeToken", "denied", "missing token")
        return False

    if not allow_mutation(payload, "revokeToken"):
        log_mutation(payload, "revokeToken", "denied", "role not allowed")
        return False

    revoke_token(token)
    log_mutation(payload, "revokeToken", "success")
    return True

@mutation.field("adminOnly")
def resolve_admin_only(_, info):
    token = info.context.get("token")
    payload = decode_token(token)
    if not payload:
        log_mutation({}, "adminOnly", "denied", "missing token")
        return "Access denied"

    if not allow_mutation(payload, "adminOnly"):
        log_mutation(payload, "adminOnly", "denied", "role not allowed")
        return "Access denied"

    log_mutation(payload, "adminOnly", "success")
    return "Admin mutation executed"
