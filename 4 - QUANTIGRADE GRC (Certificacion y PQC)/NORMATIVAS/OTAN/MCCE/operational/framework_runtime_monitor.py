#!/usr/bin/env python3
"""
framework_runtime_monitor.py - Operational Layer Runtime Monitor for MCCE_CIBERDEFENSA_MILITAR_OTAN.
Enforces military tactical telemetry, STIX 2.1 events, circuit breakers, and classified data sanitization.
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
        self.framework_id = "MCCE_CIBERDEFENSA_MILITAR_OTAN"
        self.telemetry = RuntimeTelemetryCollector(self.framework_id)
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=20.0)

    def monitor_transaction(self, raw_payload: str, latency_ms: float = 8.5) -> dict:
        """Sanitizes PII, detects secrets, and records military cyberdefense telemetry through circuit breaker."""
        def _execute():
            sanitized_text, pii_stats = PIISanitizer.sanitize(raw_payload)
            secret_findings = SecretDetector.scan(sanitized_text)
            status = "WARNING" if secret_findings else "SUCCESS"
            evt = self.telemetry.record_event(
                event_name="MCCE_TACTICAL_CYBERDEFENSE_HEARTBEAT",
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
    res = monitor.monitor_transaction("Evento táctico clasificado para Operador DNI 33445566D en WANDEF.")
    print("MCCE Monitor Output:", res)
