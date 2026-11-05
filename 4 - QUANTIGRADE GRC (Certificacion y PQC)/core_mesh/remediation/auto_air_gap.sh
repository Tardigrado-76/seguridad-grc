#!/usr/bin/env bash
# =============================================================================
# Quantigrade GCR Auto-Air-Gap Script (Linux / macOS)
# MITRE ATT&CK: T1562.004 - Impair Defenses: Disable or Modify System Firewall
# =============================================================================
set -euo pipefail

TRIGGER_ID="${1:-UNKNOWN}"
DRY_RUN="${2:-0}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/../../reports"
LOG_FILE="${LOG_DIR}/air_gap_activations.log"

mkdir -p "${LOG_DIR}"
echo "[${TIMESTAMP}] T1562.004 - Air-Gap trigger by: ${TRIGGER_ID} (DryRun: ${DRY_RUN})" >> "${LOG_FILE}"

if [[ "${DRY_RUN}" == "1" || "${DRY_RUN}" == "true" ]]; then
    echo "[QUANTIGRADE AIR-GAP] DRY-RUN active. Skipping firewall iptables modification."
    exit 0
fi

PORTS=(8000 8010 8443)

if command -v iptables &> /dev/null; then
    for PORT in "${PORTS[@]}"; do
        iptables -D INPUT  -p tcp --dport "${PORT}" -j DROP 2>/dev/null || true
        iptables -D OUTPUT -p tcp --dport "${PORT}" -j DROP 2>/dev/null || true
        iptables -A INPUT  -p tcp --dport "${PORT}" -j DROP
        iptables -A OUTPUT -p tcp --dport "${PORT}" -j DROP
    done
    echo "[${TIMESTAMP}] iptables: ports ${PORTS[*]} blocked." >> "${LOG_FILE}"
elif command -v pfctl &> /dev/null; then
    for PORT in "${PORTS[@]}"; do
        echo "block in proto tcp from any to any port ${PORT}" | pfctl -f - 2>/dev/null || true
        echo "block out proto tcp from any to any port ${PORT}" | pfctl -f - 2>/dev/null || true
    done
    echo "[${TIMESTAMP}] pfctl: ports ${PORTS[*]} blocked." >> "${LOG_FILE}"
else
    echo "[${TIMESTAMP}] WARNING: Neither iptables nor pfctl found." >> "${LOG_FILE}"
fi

echo "[QUANTIGRADE AIR-GAP] Host perimeter network isolation active."
exit 0

