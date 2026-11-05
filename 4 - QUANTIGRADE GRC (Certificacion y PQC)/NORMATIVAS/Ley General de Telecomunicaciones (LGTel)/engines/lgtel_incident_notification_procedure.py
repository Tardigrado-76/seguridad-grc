"""
LGTel Incident Notification Procedure Engine
Cumplimiento Ley 11/2022 General de Telecomunicaciones (Art. 111 y concordantes).
Procedimiento de escalado y notificación obligatoria de incidentes significativos de seguridad de redes a las autoridades competentes.
"""

import time
from typing import Dict, Any, List, Optional


class LGTelIncidentNotifier:
    # Niveles de impacto según CNMC / INCIBE / Secretaría de Estado de Telecomunicaciones
    SEVERITY_LEVELS = ["BAJO", "MEDIO", "ALTO", "CRITICO"]

    def __init__(self, authority_endpoint: str = "https://sede.mineco.gob.es/teleco/incidentes"):
        self.authority_endpoint = authority_endpoint
        self.notification_log: List[Dict[str, Any]] = []

    def evaluate_significance(self, users_affected: int, duration_minutes: int, network_service: str) -> Dict[str, Any]:
        """Evalúa si el incidente cumple el umbral del Art. 111 para notificación formal."""
        is_significant = (users_affected >= 5000) or (duration_minutes >= 60)
        level = "CRITICO" if users_affected >= 50000 or duration_minutes >= 180 else ("ALTO" if is_significant else "MEDIO")
        
        return {
            "is_significant": is_significant,
            "severity_level": level,
            "mandatory_notification": is_significant,
            "max_hours_to_notify": 24 if is_significant else 72
        }

    def generate_regulatory_notice(self, incident_id: str, users_affected: int, root_cause: str) -> Dict[str, Any]:
        """Genera el payload estructurado para la notificación formal del incidente."""
        notice = {
            "incident_id": incident_id,
            "legal_framework": "Ley 11/2022 General de Telecomunicaciones - Art. 111",
            "timestamp": time.time(),
            "users_affected": users_affected,
            "root_cause_summary": root_cause,
            "status": "DRAFT_PENDING_SUBMISSION",
            "authority_recipient": self.authority_endpoint
        }
        self.notification_log.append(notice)
        return notice
