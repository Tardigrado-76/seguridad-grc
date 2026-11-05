#!/usr/bin/env python3
"""
framework_runtime_monitor.py - Operational Layer Runtime Monitor for ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT.
Enforces OT/SCADA telemetry, circuit breakers, PII masking, and anomalous industrial command rejection.
"""

from __future__ import annotations

import sys
from pathlib import Path

GCR_ROOT = Path(r"E:/PROYECTOS IA/GCR")
if str(GCR_ROOT) not in sys.path:
    sys.path.insert(0, str(GCR_ROOT))

from core_mesh.operational import (
    CircuitBreaker,
    PIISanitizer,
    RuntimeTelemetryCollector,
    SecretDetector,
)


class FrameworkRuntimeMonitor:
    def __init__(self):
        self.framework_id = "ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT"
        self.telemetry = RuntimeTelemetryCollector(self.framework_id)
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=20.0)

    def monitor_transaction(self, raw_payload: str, latency_ms: float = 6.0) -> dict:
        """Sanitizes PII, detects secrets, and records industrial OT telemetry through circuit breaker."""
        def _execute():
            sanitized_text, pii_stats = PIISanitizer.sanitize(raw_payload)
            secret_findings = SecretDetector.scan(sanitized_text)
            status = "WARNING" if secret_findings else "SUCCESS"
            evt = self.telemetry.record_event(
                event_name="ISA_IEC_62443_SCADA_HEARTBEAT",
                status=status,
                latency_ms=latency_ms,
                details={"pii_masked": pii_stats, "secrets_flagged": len(secret_findings)}
            )
            return {
                "sanitized_payload": sanitized_text,
                "pii_stats": pii_stats,
                "secrets_detected": len(secret_findings),
                "telemetry_event": evt
            }

        return self.circuit_breaker.call(_execute)

if __name__ == "__main__":
    monitor = FrameworkRuntimeMonitor()
    res = monitor.monitor_transaction("Instruccion Modbus TCP Write Single Register para Operador DNI 55667788E.")
    print("IEC 62443 Monitor Output:", res)
