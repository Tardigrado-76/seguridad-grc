"""producer_simulator.py — Real-Time Telemetry & Security Log Generator Simulator.
==============================================================================
Generador de eventos sintéticos para pruebas de carga y simulación de incidentes
de ciberseguridad en el bus de eventos corporativo.
"""

import random
import sys
import time
import uuid
from typing import Any


class TelemetryEventProducer:
    """Generador sintético de telemetría y eventos de seguridad."""

    EVENT_TEMPLATES = [
        # Normal Traffic
        {"service": "api-gateway", "action": "http_get_200", "severity": "INFO"},
        {"service": "auth-service", "action": "jwt_token_issued", "severity": "INFO"},
        {"service": "storage-service", "action": "s3_get_object", "severity": "INFO"},

        # Incident Traffic (DORA / ENS / EU AI Act / RGPD)
        {"service": "core-banking", "action": "service_down database_unreachable timeout", "severity": "CRITICAL"},
        {"service": "iam-vault", "action": "unauthorized_admin privilege_escalation sudo_abuse", "severity": "HIGH"},
        {"service": "llm-inference", "action": "prompt_injection jailbreak override_guardrail", "severity": "HIGH"},
        {"service": "customer-db", "action": "bulk_export_pii data_leak credit_card_dump", "severity": "CRITICAL"},
        {"service": "ci-cd-runner", "action": "sri_mismatch untrusted_registry malicious_tarball", "severity": "MEDIUM"},
    ]

    @classmethod
    def generate_event(cls, is_incident: bool = False) -> dict[str, Any]:
        """Genera un evento individual estructurado."""
        if is_incident:
            template = random.choice(cls.EVENT_TEMPLATES[3:])
        else:
            template = random.choice(cls.EVENT_TEMPLATES[:3])

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "service": template["service"],
            "action": template["action"],
            "user_id": f"usr_{random.randint(1000, 9999)}",
            "ip_address": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "metadata": {
                "environment": "production",
                "datacenter": "eu-central-1",
            },
        }

    @classmethod
    def generate_batch(cls, size: int = 50, incident_ratio: float = 0.2) -> list[dict[str, Any]]:
        """Genera un lote de eventos con una proporción controlada de incidentes."""
        batch = []
        for _ in range(size):
            is_incident = random.random() < incident_ratio
            batch.append(cls.generate_event(is_incident))
        return batch


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sample_batch = TelemetryEventProducer.generate_batch(size=10, incident_ratio=0.5)
    for _ev in sample_batch:
        pass
