#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

CERT_DIR="${1:?CERT_DIR required}"
mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

ROOT_KEY="${CERT_DIR}/root_ca.key.pem"
ROOT_CRT="${CERT_DIR}/root_ca.crt.pem"
INT_KEY="${CERT_DIR}/intermediate.key.pem"
INT_CRT="${CERT_DIR}/intermediate.crt.pem"
SERVER_KEY="${CERT_DIR}/server.key.pem"
SERVER_CSR="${CERT_DIR}/server.csr.pem"
SERVER_CRT="${CERT_DIR}/server.crt.pem"
BUNDLE_PEM="${CERT_DIR}/mysql_server_bundle.pem"
OPENSSL_CNF="${CERT_DIR}/openssl.cnf"
CSR_INT="${CERT_DIR}/intermediate.csr.pem"

cat > "${OPENSSL_CNF}" <<'EOF'
[ req ]
default_bits = 2048
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[ dn ]
C = US
ST = State
L = Locality
O = ExampleOrg
OU = ExampleUnit
CN = localhost

[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash

[ v3_intermediate_ca ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ v3_server ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

if [ ! -f "${ROOT_KEY}" ] || [ ! -f "${ROOT_CRT}" ]; then
  openssl genrsa -out "${ROOT_KEY}" 4096
  openssl req -x509 -new -nodes -key "${ROOT_KEY}" -sha256 -days 3650 \
    -subj "/C=US/ST=State/L=Local/O=ExampleOrg/OU=RootCA/CN=MySQL Root CA" \
    -out "${ROOT_CRT}" -extensions v3_ca -config "${OPENSSL_CNF}"
fi

if [ ! -f "${INT_KEY}" ] || [ ! -f "${INT_CRT}" ]; then
  openssl genrsa -out "${INT_KEY}" 4096
  openssl req -new -key "${INT_KEY}" -subj "/C=US/ST=State/L=Local/O=ExampleOrg/OU=Intermediate/CN=MySQL Intermediate" \
    -out "${CSR_INT}" -config "${OPENSSL_CNF}"
  openssl x509 -req -in "${CSR_INT}" -CA "${ROOT_CRT}" -CAkey "${ROOT_KEY}" \
    -CAcreateserial -out "${INT_CRT}" -days 3650 -sha256 -extfile "${OPENSSL_CNF}" -extensions v3_intermediate_ca
fi

if [ ! -f "${SERVER_KEY}" ] || [ ! -f "${SERVER_CRT}" ]; then
  openssl genrsa -out "${SERVER_KEY}" 2048
  openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" -subj "/CN=localhost" -config "${OPENSSL_CNF}"
  openssl x509 -req -in "${SERVER_CSR}" -CA "${INT_CRT}" -CAkey "${INT_KEY}" -CAcreateserial \
    -out "${SERVER_CRT}" -days 825 -sha256 -extfile "${OPENSSL_CNF}" -extensions v3_server
fi

cat "${ROOT_CRT}" > "${BUNDLE_PEM}"
cat "${INT_CRT}" >> "${BUNDLE_PEM}"
cat "${SERVER_CRT}" >> "${BUNDLE_PEM}"
cat "${SERVER_KEY}" >> "${BUNDLE_PEM}"
chmod 600 "${BUNDLE_PEM}"

echo "Generated CA and bundle at ${BUNDLE_PEM}"
