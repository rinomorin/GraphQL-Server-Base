#!/bin/bash
set -e

CERT_DIR=/etc/mysql_certs
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Root CA
openssl genrsa -out root_ca_key.pem 4096
openssl req -x509 -new -nodes -key root_ca_key.pem -sha256 -days 3650 \
  -subj "/CN=MariaDB Root CA" \
  -out root_ca_crt.pem

# Client key
openssl genrsa -out client.key.pem 2048

# Client CSR with CN=MorinSoft
openssl req -new -key client.key.pem -out client.csr.pem -subj "/CN=MorinSoft"

# Client cert signed by root CA
openssl x509 -req \
  -in client.csr.pem \
  -CA root_ca_crt.pem \
  -CAkey root_ca_key.pem \
  -CAcreateserial \
  -out client.crt.pem \
  -days 365 \
  -sha256

# Bundle for server-side validation
cp root_ca_crt.pem mysql_server_bundle.pem

echo "✅ CA and client certs generated with CN=MorinSoft"
