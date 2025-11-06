#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# 🔧 Configurable paths and credentials
MYSQL_DATA="${MYSQL_DATA:-/var/lib/mysql}"
CERT_DIR="${CERT_DIR:-/etc/mysql_certs}"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-One2LoadT00~}"

REMOTE_TLS_USER="remote_tls"
REMOTE_TLS_PASSWORD="SecureTLSPass"

# 🧼 Ensure directories exist and are secure
mkdir -p "${MYSQL_DATA}" "${CERT_DIR}"
chown -R mysql:mysql "${MYSQL_DATA}" "${CERT_DIR}" || true
chmod 700 "${MYSQL_DATA}" "${CERT_DIR}" || true

# 🔐 Generate certs if missing
if [ ! -f "${CERT_DIR}/server_crt.pem" ]; then
  echo "[entrypoint] Running generate_ca.sh..."
  /usr/local/bin/generate_ca.sh "${CERT_DIR}" "MorinSoft"
fi

# ⚙️ Initialize DB if missing
if [ ! -d "${MYSQL_DATA}/mysql" ]; then
  echo "[entrypoint] Initializing MariaDB data directory..."
  mariadb-install-db --datadir="${MYSQL_DATA}"

  echo "[entrypoint] Starting temporary MariaDB for bootstrap..."
  mariadbd-safe --datadir="${MYSQL_DATA}" --socket=/tmp/mysql.sock &
  MYSQLD_PID=$!

  for i in $(seq 1 30); do
    if mariadb-admin --socket=/tmp/mysql.sock ping &>/dev/null; then break; fi
    sleep 1
    if [ "$i" -eq 30 ]; then echo "[entrypoint] ERROR: MariaDB socket timeout"; exit 1; fi
  done

  echo "[entrypoint] Injecting TLS users and grants..."
  mariadb --socket=/tmp/mysql.sock <<EOF
    -- Root user for localhost (socket access)
    CREATE USER IF NOT EXISTS 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}' REQUIRE SSL;
    GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION;

    -- Root user for literal IP (TLS access)
    CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}' REQUIRE SSL;
    GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;

    -- Remote TLS user for dynamic IPs
    CREATE USER IF NOT EXISTS '${REMOTE_TLS_USER}'@'192.168.100.%' IDENTIFIED BY '${REMOTE_TLS_PASSWORD}' REQUIRE SSL;
    GRANT ALL PRIVILEGES ON *.* TO '${REMOTE_TLS_USER}'@'192.168.100.%' WITH GRANT OPTION;

    FLUSH PRIVILEGES;
EOF

  echo "[entrypoint] Shutting down temporary MariaDB..."
  mariadb-admin --socket=/tmp/mysql.sock shutdown || true
  wait "${MYSQLD_PID}" 2>/dev/null || true
fi

# 🚀 Start MariaDB with TLS
echo "[entrypoint] Starting MariaDB with TLS enforcement..."
exec mariadbd \
  --datadir="${MYSQL_DATA}" \
  --ssl-ca="${CERT_DIR}/mysql_server_bundle.pem" \
  --ssl-cert="${CERT_DIR}/server_crt.pem" \
  --ssl-key="${CERT_DIR}/server_key.pem" \
  --bind-address=0.0.0.0 \
  --require-secure-transport=ON
