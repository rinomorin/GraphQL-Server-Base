#!/usr/bin/env bash
set -euo pipefail

# Adjust these if you want different names or credentials
NETWORK_NAME="graphql-net"
PG_CONTAINER="postgres"
APP_CONTAINER="graphql-app"
MIGRATE_RUNNER="run-migrations"
SEED_RUNNER="seed-users"
PG_VOLUME="graphql_pgdata"
PG_IMAGE="docker.io/library/postgres:15"
APP_IMAGE="graphql-app"
HOST_PROJECT_DIR="$(pwd)"
MOUNT_SERVER_DIR="${HOST_PROJECT_DIR}/graphql-base/server"
MOUNT_DB_DIR="${HOST_PROJECT_DIR}/graphql-base/db"
PROJECT_DSN="postgresql://project_user:project_pass@postgres:5432/graphql_base"
MIGRATIONS_PY="/opt/app/projects/GraphQL-Server-Base/graphql-base/db/run_migrations.py"
SEED_PY="/opt/app/projects/GraphQL-Server-Base/graphql-base/db/seed_users.py"

echo "1) Stopping and removing containers, volume, network, image (if present)"
podman rm -f "${APP_CONTAINER}" 2>/dev/null || true
podman rm -f "${PG_CONTAINER}" 2>/dev/null || true
podman rm -f "${MIGRATE_RUNNER}" 2>/dev/null || true
podman rm -f "${SEED_RUNNER}" 2>/dev/null || true

echo "2) Remove named volume if exists"
podman volume rm "${PG_VOLUME}" 2>/dev/null || true

echo "3) Remove network if exists"
podman network rm "${NETWORK_NAME}" 2>/dev/null || true

echo "4) Build app image (Dockerfile must be at project root)"
podman build -t "${APP_IMAGE}" -f Dockerfile .

echo "5) Recreate network and named volume"
podman network create "${NETWORK_NAME}"
podman volume create "${PG_VOLUME}"

echo "6) Run Postgres container with fresh named volume"
podman run -d --name "${PG_CONTAINER}" \
  --network "${NETWORK_NAME}" \
  -e POSTGRES_PASSWORD=project_pass \
  -e POSTGRES_USER=project_user \
  -e POSTGRES_DB=graphql_base \
  -v "${PG_VOLUME}":/var/lib/postgresql/data \
  -p 5432:5432 \
  "${PG_IMAGE}"

echo "Waiting for Postgres to accept connections..."
# wait loop (10s timeout x12 = 120s)
for i in {1..12}; do
  if podman run --rm --network "${NETWORK_NAME}" "${PG_IMAGE}" \
     psql "postgresql://project_user:project_pass@${PG_CONTAINER}:5432/graphql_base" -c "SELECT 1;" >/dev/null 2>&1; then
    echo "Postgres ready"
    break
  fi
  echo "Postgres not ready yet, retrying ($i/12)..."
  sleep 10
  if [ "$i" -eq 12 ]; then
    echo "Postgres did not become ready within timeout"; podman logs -f "${PG_CONTAINER}" --tail 200 || true; exit 1
  fi
done

echo "7) Run migrations (mount only required folders)"
podman run --rm --name "${MIGRATE_RUNNER}" \
  --network "${NETWORK_NAME}" \
  -e PROJECT_DB_DSN="${PROJECT_DSN}" \
  -v "${MOUNT_DB_DIR}":/opt/app/projects/GraphQL-Server-Base/graphql-base/db:Z \
  -v "${MOUNT_SERVER_DIR}":/opt/app/projects/GraphQL-Server-Base/graphql-base/server:Z \
  "${APP_IMAGE}" \
  python "${MIGRATIONS_PY}"

echo "8) Run seeder (only if file exists)"
if [ -f "${HOST_PROJECT_DIR}/graphql-base/db/seed_users.py" ]; then
  podman run --rm --name "${SEED_RUNNER}" \
    --network "${NETWORK_NAME}" \
    -e PROJECT_DB_DSN="${PROJECT_DSN}" \
    -v "${MOUNT_DB_DIR}":/opt/app/projects/GraphQL-Server-Base/graphql-base/db:Z \
    -v "${MOUNT_SERVER_DIR}":/opt/app/projects/GraphQL-Server-Base/graphql-base/server:Z \
    "${APP_IMAGE}" \
    python "${SEED_PY}"
else
  echo "seed_users.py not found; skipping seeding"
fi

echo "9) Start app container with server code mounted"
podman run -d --name "${APP_CONTAINER}" \
  --network "${NETWORK_NAME}" \
  -e PROJECT_DB_DSN="${PROJECT_DSN}" \
  -p 5000:5000 \
  -v "${MOUNT_SERVER_DIR}":/opt/app/projects/GraphQL-Server-Base/graphql-base/server:Z \
  "${APP_IMAGE}"

echo "10) Tail logs (Postgres then app) for quick check"
echo "---- Postgres logs ----"
podman logs "${PG_CONTAINER}" --tail 50
echo "---- App logs ----"
podman logs "${APP_CONTAINER}" --tail 50

echo "11) Test GraphQL login (rino/testpass) curl example:"
echo "curl -sS -X POST http://localhost:5000/graphql -H 'Content-Type: application/json' -d '{\"query\":\"mutation { login(username: \\\"rino\\\", password: \\\"testpass\\\") { accessToken refreshToken tokenType issuedAt expiresAt scope role userId } }\"}'"

echo "Done."
