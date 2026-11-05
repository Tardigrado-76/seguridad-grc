#!/bin/bash
# Script para generar CA local y certificados mTLS (Server y Client)

mkdir -p certs
cd certs

# 1. Crear la Autoridad Certificadora (CA)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=BunkerOS-CA/O=BunkerCorp/C=ES"

# 2. Certificado del Servidor (FastAPI)
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=localhost/O=BunkerCorp/C=ES"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# 3. Certificado del Cliente (BFF NestJS)
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=Bunker-BFF/O=BunkerCorp/C=ES"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt

echo "✅ Certificados mTLS generados en ./certs"
