#!/usr/bin/env python3
"""
framework_runtime_monitor.py - Operational Layer Runtime Monitor for ITAR_EAR_DUAL_USE_EXPORT_CONTROL.
Enforces technical data leak prevention, circuit breakers, and telemetry for export-controlled transactions.
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
        self.framework_id = "ITAR_EAR_DUAL_USE_EXPORT_CONTROL"
        self.telemetry = RuntimeTelemetryCollector(self.framework_id)
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=20.0)

    def monitor_transaction(self, raw_payload: str, latency_ms: float = 14.0) -> dict:
        """Sanitizes PII, detects secrets, and records export-control telemetry through circuit breaker."""
        def _execute():
            sanitized_text, pii_stats = PIISanitizer.sanitize(raw_payload)
            secret_findings = SecretDetector.scan(sanitized_text)
            status = "WARNING" if secret_findings else "SUCCESS"
            evt = self.telemetry.record_event(
                event_name="ITAR_EAR_EXPORT_CONTROL_HEARTBEAT",
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
    res = monitor.monitor_transaction("Transferencia ECCN 5D002 para Usuario DNI 00112233C.")
    print("ITAR Monitor Output:", res)
