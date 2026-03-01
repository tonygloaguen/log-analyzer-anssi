#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Génération des certificats TLS pour le développement local
# ANSSI : TLS mutuel (mTLS) entre agents de collecte
#
# EN PRODUCTION : remplacer par des certificats émis par une PKI d'entreprise
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

CERTS_DIR="${1:-./certs}"
mkdir -p "$CERTS_DIR"

echo "→ Génération des certificats TLS dans $CERTS_DIR"

# CA (Autorité de Certification)
openssl genrsa -out "$CERTS_DIR/ca.key" 4096
openssl req -new -x509 -days 3650 -key "$CERTS_DIR/ca.key" \
    -out "$CERTS_DIR/ca.crt" \
    -subj "/C=FR/O=log-analyzer-anssi/CN=CA-log-analyzer"

# Certificat serveur (Loki, API)
openssl genrsa -out "$CERTS_DIR/server.key" 2048
openssl req -new -key "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.csr" \
    -subj "/C=FR/O=log-analyzer-anssi/CN=server"

openssl x509 -req -days 365 \
    -in "$CERTS_DIR/server.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/server.crt" \
    -extfile <(printf "subjectAltName=DNS:loki,DNS:api,DNS:localhost,IP:127.0.0.1")

# Certificat client (Fluent Bit)
openssl genrsa -out "$CERTS_DIR/client.key" 2048
openssl req -new -key "$CERTS_DIR/client.key" \
    -out "$CERTS_DIR/client.csr" \
    -subj "/C=FR/O=log-analyzer-anssi/CN=fluent-bit-collector"

openssl x509 -req -days 365 \
    -in "$CERTS_DIR/client.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/client.crt"

# Permissions restrictives (ANSSI)
chmod 600 "$CERTS_DIR"/*.key
chmod 644 "$CERTS_DIR"/*.crt

echo "✓ Certificats générés dans $CERTS_DIR :"
ls -la "$CERTS_DIR/"

echo ""
echo "Copier le dossier certs/ dans le volume Docker :"
echo "  docker volume create certs"
echo "  docker run --rm -v \$(pwd)/certs:/src -v certs:/dest alpine cp -r /src/. /dest/"
