"""log_auditor_agent.py — Real-Time Streaming Compliance & Security Auditor Agent.
==============================================================================
Agente de IA autónomo para la auditoría reactiva en tiempo real de flujos de eventos.
Analiza logs del sistema, eventos de identidad (IAM), accesos a APIs y tráfico de red
contra directivas regulatorias (EU AI Act, DORA, ENS Alta, NIS2, RGPD).

Cumplimiento: DORA Art. 10 (Detección de Actividades Anómalas), ENS Alta op.mon.1 (Monitorización Continua)
"""

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("StreamingAuditor.Agent")


class SeverityLevel:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class StreamLogAuditorAgent:
    """Agente evaluador en tiempo real de eventos de telemetría y seguridad."""

    # Reglas de Detección Heurística y Regulatoria
    COMPLIANCE_PATTERNS = [
        {
            "id": "RULE-DORA-001",
            "name": "Fallo Masivo en Servicio TIC Crítico",
            "framework": "DORA Art. 18",
            "pattern": r"(service_down|timeout|database_unreachable|cluster_degraded|outage)",
            "min_occurrences": 3,
            "severity": SeverityLevel.CRITICAL,
            "action_required": "Iniciar protocolo de notificación de incidentes graves (4h).",
        },
        {
            "id": "RULE-ENS-002",
            "name": "Intento de Escalada de Privilegios no Autorizada",
            "framework": "ENS Alta op.acc.4",
            "pattern": r"(privilege_escalation|sudo_abuse|unauthorized_admin|shadow_admin)",
            "min_occurrences": 1,
            "severity": SeverityLevel.HIGH,
            "action_required": "Revocación inmediata de sesión y registro en Audit Bunker.",
        },
        {
            "id": "RULE-AIACT-003",
            "name": "Intento de Prompt Injection / Evasión de Guardrails en LLM",
            "framework": "EU AI Act Art. 15 / OWASP LLM01",
            "pattern": r"(prompt_injection|jailbreak|ignore_previous_instructions|override_guardrail)",
            "min_occurrences": 1,
            "severity": SeverityLevel.HIGH,
            "action_required": "Bloqueo perimetral de IP y trazado forense.",
        },
        {
            "id": "RULE-RGPD-004",
            "name": "Exfiltración Masiva de Datos Personales (PII)",
            "framework": "RGPD Art. 33",
            "pattern": r"(bulk_export_pii|unencrypted_ssn|credit_card_dump|data_leak)",
            "min_occurrences": 1,
            "severity": SeverityLevel.CRITICAL,
            "action_required": "Aislamiento de base de datos y notificación a la AEPD (72h).",
        },
        {
            "id": "RULE-NIS2-005",
            "name": "Conexión a Repositorio o Dependencia no Verificada",
            "framework": "NIS2 Art. 21 (Supply Chain)",
            "pattern": r"(unsigned_package|sri_mismatch|untrusted_registry|malicious_tarball)",
            "min_occurrences": 1,
            "severity": SeverityLevel.MEDIUM,
            "action_required": "Bloqueo del pipeline CI/CD y escaneo de vulnerabilidades.",
        },
    ]

    def __init__(self) -> None:
        self.incident_history: list[dict[str, Any]] = []

    @staticmethod
    def _compute_hash(data: dict[str, Any]) -> str:
        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def evaluate_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Evalúa un evento individual en streaming contra las políticas de cumplimiento.
        Retorna un objeto IncidentAlert si detecta una anomalía.
        """
        event_str = json.dumps(event).lower()
        matched_rules = []

        for rule in self.COMPLIANCE_PATTERNS:
            matches = len(re.findall(rule["pattern"], event_str))
            if matches >= rule["min_occurrences"]:
                matched_rules.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "framework": rule["framework"],
                    "severity": rule["severity"],
                    "action_required": rule["action_required"],
                    "matched_count": matches,
                })

        if not matched_rules:
            return None

        # Determinar severidad máxima
        severity_order = [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        highest_severity = max(matched_rules, key=lambda r: severity_order.index(r["severity"]))["severity"]

        incident = {
            "incident_id": f"INC-{int(time.time()*1000)}-{event.get('event_id', '0')[:6]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_service": event.get("service", "unknown"),
            "event_type": event.get("event_type", "security_event"),
            "highest_severity": highest_severity,
            "matched_rules": matched_rules,
            "raw_event_summary": {
                "user_id": event.get("user_id", "anonymous"),
                "ip_address": event.get("ip_address", "internal"),
                "action": event.get("action", "unknown"),
            },
            "cryptographic_proof_sha256": self._compute_hash(event),
            "status": "OPEN",
        }

        self.incident_history.append(incident)
        logger.warning(
            f"🚨 [EventAuditor] Incidente {incident['incident_id']} detectado! "
            f"Severidad: {highest_severity} | Reglas: {[r['rule_id'] for r in matched_rules]}",
        )
        return incident

    def get_incident_metrics(self) -> dict[str, Any]:
        """Devuelve estadísticas de incidentes procesados en streaming."""
        total = len(self.incident_history)
        critical_count = sum(1 for i in self.incident_history if i["highest_severity"] == SeverityLevel.CRITICAL)
        high_count = sum(1 for i in self.incident_history if i["highest_severity"] == SeverityLevel.HIGH)

        return {
            "total_incidents_logged": total,
            "critical_incidents": critical_count,
            "high_incidents": high_count,
            "recent_incidents": self.incident_history[-10:],
        }
