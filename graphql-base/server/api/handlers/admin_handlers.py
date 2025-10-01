from server.api.auth.token import decode_token
from server.api.permissions import allow_mutation, require_mutation_scope, log_mutation

def resolve_admin_only(_, info):
    token = info.context.get("token")
    if not token:
        log_mutation({}, "adminOnly", "denied", "missing token")
        return "Access denied"

    payload = decode_token(token)
    if not payload:
        log_mutation({}, "adminOnly", "denied", "invalid token")
        return "Access denied"

    if not allow_mutation(payload, "adminOnly"):
        log_mutation(payload, "adminOnly", "denied", "role not allowed")
        return "Access denied"

    if not require_mutation_scope(payload, "adminOnly"):
        log_mutation(payload, "adminOnly", "denied", "missing scope")
        return "Access denied"

    log_mutation(payload, "adminOnly", "success")
    return "Admin mutation executed"
