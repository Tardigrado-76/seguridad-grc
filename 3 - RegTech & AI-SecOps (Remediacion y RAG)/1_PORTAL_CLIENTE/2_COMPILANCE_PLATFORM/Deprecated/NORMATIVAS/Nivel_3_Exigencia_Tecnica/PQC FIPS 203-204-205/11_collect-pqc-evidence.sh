#!/bin/bash
# =============================================================================
# BunkerOS — PQC Validation Evidence Collector
# =============================================================================
# Genera evidencias verificables de soporte Post-Quantum Cryptography.
# Cumplimiento: FIPS 203 ML-KEM, FIPS 204 ML-DSA, ENS Alta, NIS2 Art.21
#
# Ejecución: chmod +x scripts/collect-pqc-evidence.sh && ./scripts/collect-pqc-evidence.sh
# Requiere: OpenSSL 3.x con oqs-provider, NGINX compilado con PQC, testssl.sh
# =============================================================================

set -euo pipefail

EVIDENCE_DIR="evidence/pqc"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
mkdir -p "$EVIDENCE_DIR"

echo "═══════════════════════════════════════════════════════════════"
echo " BunkerOS PQC Evidence Collector — $TIMESTAMP"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. OpenSSL Version & Provider Inventory ─────────────────────────────────
echo "[1/6] Collecting OpenSSL version and providers..."
{
  echo "=== OpenSSL Version ==="
  openssl version -a 2>&1 || echo "ERROR: OpenSSL not found"
  echo ""
  echo "=== OpenSSL Providers ==="
  openssl list -providers 2>&1 || echo "ERROR: Cannot list providers"
  echo ""
  echo "=== OQS Provider Algorithms ==="
  openssl list -kem-algorithms 2>&1 | grep -i "kyber\|mlkem\|ML-KEM" || echo "WARNING: No PQC KEM algorithms found"
  echo ""
  openssl list -signature-algorithms 2>&1 | grep -i "dilithium\|mldsa\|ML-DSA\|slhdsa\|SLH-DSA" || echo "WARNING: No PQC signature algorithms found"
} > "$EVIDENCE_DIR/openssl_inventory.txt" 2>&1

# ─── 2. NGINX Build Configuration ────────────────────────────────────────────
echo "[2/6] Collecting NGINX build info..."
{
  echo "=== NGINX Version ==="
  nginx -V 2>&1 || echo "ERROR: NGINX not found or not in PATH"
  echo ""
  echo "=== TLS Module ==="
  nginx -V 2>&1 | grep -o "built with OpenSSL.*" || echo "WARNING: Cannot determine OpenSSL linkage"
} > "$EVIDENCE_DIR/nginx_build.txt" 2>&1

# ─── 3. Cipher Suite Inventory ───────────────────────────────────────────────
echo "[3/6] Generating cipher inventory..."
{
  echo "{"
  echo "  \"timestamp\": \"$TIMESTAMP\","
  echo "  \"openssl_version\": \"$(openssl version 2>/dev/null || echo 'N/A')\","
  echo "  \"tls13_ciphers\": ["
  openssl ciphers -v -tls1_3 2>/dev/null | awk '{printf "    \"%s\",\n", $1}' | sed '$ s/,$//'
  echo "  ],"
  echo "  \"pqc_kems\": ["
  openssl list -kem-algorithms 2>/dev/null | grep -i "kyber\|mlkem\|ML-KEM" | awk '{printf "    \"%s\",\n", $1}' | sed '$ s/,$//' || echo "    \"NONE_DETECTED\""
  echo "  ],"
  echo "  \"pqc_signatures\": ["
  openssl list -signature-algorithms 2>/dev/null | grep -i "dilithium\|mldsa\|ML-DSA" | awk '{printf "    \"%s\",\n", $1}' | sed '$ s/,$//' || echo "    \"NONE_DETECTED\""
  echo "  ]"
  echo "}"
} > "$EVIDENCE_DIR/cipher_inventory.json" 2>&1

# ─── 4. TLS 1.3 Handshake Capture ────────────────────────────────────────────
echo "[4/6] Attempting TLS 1.3 handshake capture..."
{
  echo "=== TLS 1.3 Handshake Test (localhost:443) ==="
  echo "Q" | openssl s_client -connect 127.0.0.1:443 -tls1_3 -brief 2>&1 || echo "WARNING: TLS 1.3 handshake failed (server may not be running)"
} > "$EVIDENCE_DIR/tls13_handshake.txt" 2>&1

# ─── 5. ML-KEM Hybrid Handshake Capture ──────────────────────────────────────
echo "[5/6] Attempting ML-KEM hybrid handshake..."
{
  echo "=== X25519MLKEM768 Hybrid Handshake Test ==="
  echo "Q" | openssl s_client -connect 127.0.0.1:443 -tls1_3 -groups X25519MLKEM768 -brief 2>&1 || echo "WARNING: ML-KEM handshake failed (OQS provider may not be loaded)"
  echo ""
  echo "=== Fallback: X25519Kyber768Draft00 ==="
  echo "Q" | openssl s_client -connect 127.0.0.1:443 -tls1_3 -groups X25519Kyber768Draft00 -brief 2>&1 || echo "WARNING: Kyber draft handshake also failed"
} > "$EVIDENCE_DIR/mlkem_handshake.txt" 2>&1

# ─── 6. testssl.sh Scan (if available) ───────────────────────────────────────
echo "[6/6] Running testssl.sh scan..."
if command -v testssl.sh &> /dev/null || [ -f "./testssl.sh/testssl.sh" ]; then
  TESTSSL_CMD=$(command -v testssl.sh || echo "./testssl.sh/testssl.sh")
  {
    $TESTSSL_CMD --quiet --severity HIGH --protocols --server-defaults --headers \
      --vulnerable --std --pfs --server-preference 127.0.0.1:443 2>&1
  } > "$EVIDENCE_DIR/testssl_report.txt" 2>&1
else
  echo "WARNING: testssl.sh not found. Install: git clone https://github.com/drwetter/testssl.sh" > "$EVIDENCE_DIR/testssl_report.txt"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Evidence collection complete. Files in: $EVIDENCE_DIR/"
echo "═══════════════════════════════════════════════════════════════"
ls -la "$EVIDENCE_DIR/"
