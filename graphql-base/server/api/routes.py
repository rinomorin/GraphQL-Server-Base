from ariadne import QueryType, MutationType
from datetime import datetime, timezone

# Create Query and Mutation objects immediately so imports can't fail due to circulars
query = QueryType()
mutation = MutationType()

# Minimal ping and me resolvers here; keep token decode import local to avoid circulars
@query.field("ping")
def resolve_ping(_, info):
    return "pong"

@query.field("me")
def resolve_me(_, info):
    # local imports to avoid circular import at module load
    from server.api.auth.token import decode_token
    from server.api.permissions import require_scope, require_mutation_scope, log_mutation

    token = info.context.get("token")
    if not token:
        return None

    payload = decode_token(token)
    if not payload or not require_scope(payload, "read"):
        return None

    if not require_mutation_scope(payload, "me"):
        log_mutation(payload, "me", "denied", "missing scope")
        return None

    return {
        "user_id": payload["sub"],
        "scope": payload.get("scope", ""),
        "issued_at": payload.get("iat"),
        "trace_id": payload.get("trace_id"),
        "role": payload.get("role")
    }

# Resolver binding function — performs imports and registers handlers lazily
def bind_resolvers():
    # Avoid repeated binding
    if getattr(bind_resolvers, "_bound", False):
        return
    # Local imports to break potential circular dependencies
    from server.api.handlers.auth_handlers import (
        resolve_login,
        resolve_refresh_token,
        resolve_logout,
        resolve_revoke_token,
        resolve_revoke_rotation_chain
    )
    from server.api.handlers.admin_handlers import resolve_admin_only

    # Register mutation resolvers
    mutation.set_field("login", resolve_login)
    mutation.set_field("refreshToken", resolve_refresh_token)
    mutation.set_field("logout", resolve_logout)
    mutation.set_field("revokeToken", resolve_revoke_token)
    mutation.set_field("revokeRotationChain", resolve_revoke_rotation_chain)
    mutation.set_field("adminOnly", resolve_admin_only)

    bind_resolvers._bound = True

# Bind on import but after definitions to minimize race with other imports
try:
    bind_resolvers()
except Exception:
    # If binding fails during import-time (still possible in complex circulars),
    # leave query/mutation defined and allow the application to call bind_resolvers()
    # later during startup. Record the failure minimally.
    import traceback, sys
    sys.stderr.write("Warning: resolver binding failed during import; will retry at runtime\n")
    traceback.print_exc()
