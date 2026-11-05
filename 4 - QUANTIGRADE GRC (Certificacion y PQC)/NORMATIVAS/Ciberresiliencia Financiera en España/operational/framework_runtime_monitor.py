#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
framework_runtime_monitor.py - Operational Layer Runtime Monitor for CIBERRESILIENCIA_FINANCIERA_ES.
Utilizes GCR core_mesh operational telemetry, circuit breakers, PII sanitizers, and secret detectors.
"""

from __future__ import annotations
import sys
from pathlib import Path

# Add GCR root to sys.path
GCR_ROOT = Path(r"E:/PROYECTOS IA/GCR")
if str(GCR_ROOT) not in sys.path:
    sys.path.insert(0, str(GCR_ROOT))

from core_mesh.operational import CircuitBreaker, PIISanitizer, SecretDetector, RuntimeTelemetryCollector

class FrameworkRuntimeMonitor:
    def __init__(self):
        self.framework_id = "CIBERRESILIENCIA_FINANCIERA_ES"
        self.telemetry = RuntimeTelemetryCollector(self.framework_id)
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=20.0)

    def monitor_transaction(self, raw_payload: str, latency_ms: float = 12.5) -> dict:
        """Sanitizes PII, detects secrets, and records telemetry through a protected circuit breaker."""
        def _execute():
            sanitized_text, pii_stats = PIISanitizer.sanitize(raw_payload)
            secret_findings = SecretDetector.scan(sanitized_text)
            status = "WARNING" if secret_findings else "SUCCESS"
            evt = self.telemetry.record_event(
                event_name="BDE_CIR_2_2020_TELEMETRY",
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
    res = monitor.monitor_transaction("Usuario DNI 12345678Z con email test@empresa.es procesado.")
    print("Monitor Output:", res)
