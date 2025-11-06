#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

MYSQL_DATA="${MYSQL_DATA:-/var/lib/mysql}"
CERT_DIR="${CERT_DIR:-/etc/mysql_certs}"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-}"
MYSQL_USER="mysql"

mkdir -p "${MYSQL_DATA}" "${CERT_DIR}"
chown -R "${MYSQL_USER}":"${MYSQL_USER}" "${MYSQL_DATA}" "${CERT_DIR}" || true
chmod 700 "${MYSQL_DATA}" || true
chmod 700 "${CERT_DIR}" || true

if [ ! -f "${CERT_DIR}/mysql_server_bundle.pem" ]; then
  /usr/local/bin/generate_ca.sh "${CERT_DIR}"
  chown "${MYSQL_USER}":"${MYSQL_USER}" "${CERT_DIR}"/*.pem || true
  chmod 600 "${CERT_DIR}"/*.pem || true
fi

if [ -f "${CERT_DIR}/root_ca.crt.pem" ]; then
  cp "${CERT_DIR}/root_ca.crt.pem" /etc/pki/ca-trust/source/anchors/mysql_root_ca.crt
  update-ca-trust extract || true
fi

if [ ! -d "${MYSQL_DATA}/mysql" ]; then
  echo "Initializing MySQL datadir at ${MYSQL_DATA}..."
  mysqld --initialize-insecure --datadir="${MYSQL_DATA}" --user="${MYSQL_USER}"
  chown -R "${MYSQL_USER}":"${MYSQL_USER}" "${MYSQL_DATA}"

  mysqld_safe --datadir="${MYSQL_DATA}" --socket=/tmp/mysql.sock --pid-file=/tmp/mysql.pid &
  MYSQLD_PID=$!

  for i in $(seq 1 30); do
    if mysqladmin --socket=/tmp/mysql.sock ping &>/dev/null; then break; fi
    sleep 1
  done

  if [ -n "${MYSQL_ROOT_PASSWORD}" ]; then
    mysql --socket=/tmp/mysql.sock -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}'; FLUSH PRIVILEGES;"
  fi

  mysqladmin --socket=/tmp/mysql.sock shutdown || true
  wait "${MYSQLD_PID}" 2>/dev/null || true
fi

exec mysqld \
  --datadir="${MYSQL_DATA}" \
  --ssl-ca="${CERT_DIR}/root_ca.crt.pem" \
  --ssl-cert="${CERT_DIR}/server.crt.pem" \
  --ssl-key="${CERT_DIR}/server.key.pem" \
  --bind-address=0.0.0.0
