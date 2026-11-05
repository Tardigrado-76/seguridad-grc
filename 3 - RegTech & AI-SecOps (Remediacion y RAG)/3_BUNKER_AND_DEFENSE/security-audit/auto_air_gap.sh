#!/usr/bin/env bash
# =============================================================================
# BunkerOS Auto-Air-Gap Script (Linux / macOS)
# MITRE ATT&CK: T1562.004 - Impair Defenses: Disable or Modify System Firewall
# Invocado por IntrusionDetectionEngine cuando se supera el umbral de ráfaga.
# Uso: auto_air_gap.sh <MITRE_ID>
# =============================================================================
set -euo pipefail

TRIGGER_ID="${1:-UNKNOWN}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/../logs"
LOG_FILE="${LOG_DIR}/air_gap_activations.log"

mkdir -p "${LOG_DIR}"
echo "[${TIMESTAMP}] T1562.004 - Air-Gap activado por: ${TRIGGER_ID}" >> "${LOG_FILE}"

# Puertos BunkerOS a bloquear
PORTS=(8000 8010 8443)

if command -v iptables &> /dev/null; then
    for PORT in "${PORTS[@]}"; do
        # Eliminar reglas previas (idempotente) — ignorar si no existen
        iptables -D INPUT  -p tcp --dport "${PORT}" -j DROP 2>/dev/null || true
        iptables -D OUTPUT -p tcp --dport "${PORT}" -j DROP 2>/dev/null || true

        # Bloquear tráfico entrante y saliente
        iptables -A INPUT  -p tcp --dport "${PORT}" -j DROP
        iptables -A OUTPUT -p tcp --dport "${PORT}" -j DROP
    done
    echo "[${TIMESTAMP}] iptables: puertos ${PORTS[*]} bloqueados." >> "${LOG_FILE}"
elif command -v pfctl &> /dev/null; then
    # macOS — añadir regla de bloqueo vía pfctl
    for PORT in "${PORTS[@]}"; do
        echo "block in  proto tcp from any to any port ${PORT}" | pfctl -f - 2>/dev/null || true
        echo "block out proto tcp from any to any port ${PORT}" | pfctl -f - 2>/dev/null || true
    done
    echo "[${TIMESTAMP}] pfctl: puertos ${PORTS[*]} bloqueados." >> "${LOG_FILE}"
else
    echo "[${TIMESTAMP}] ERROR: No se encontró iptables ni pfctl." >> "${LOG_FILE}"
    exit 1
fi

echo "[BUNKER AIR-GAP] Aislamiento de red activado correctamente."
exit 0
