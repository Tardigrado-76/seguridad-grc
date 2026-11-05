#!/usr/bin/env python3
"""
dora_incident_classifier.py
DORA Art. 18 Major ICT Incident Classification & Thresholds Engine.
Compliant with joint RTS EBA/RTS/2024/02 (Criteria for major incident classification).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ICTIncidentMetrics:
    incident_id: str
    affected_users: int = 0
    downtime_minutes: int = 0
    data_loss_critical: bool = False
    estimated_loss_eur: float = 0.0


@dataclass(frozen=True)
class ClassificationResult:
    incident_id: str
    is_major: bool
    trigger_reasons: list[str] = field(default_factory=list)
    notification_window_hours: int = (
        4  # DORA initial notification: 4h from classification
    )


class DORAIncidentClassifier:
    """
    Automated classification engine for DORA Art. 18 & EBA/RTS/2024/02.
    Thresholds:
      - Client impact: >= 100,000 affected users
      - Duration: >= 120 minutes downtime
      - Economic loss: >= 100,000.0 EUR
      - Critical data integrity/confidentiality breach: True
    """

    CLIENT_IMPACT_THRESHOLD = 100_000
    DOWNTIME_MINUTES_THRESHOLD = 120
    ECONOMIC_LOSS_THRESHOLD = 100_000.0

    def classify(self, metrics: ICTIncidentMetrics) -> ClassificationResult:
        reasons: list[str] = []

        if metrics.downtime_minutes >= self.DOWNTIME_MINUTES_THRESHOLD:
            reasons.append("DOWNTIME_EXCEEDED")

        if metrics.affected_users >= self.CLIENT_IMPACT_THRESHOLD:
            reasons.append("CLIENT_IMPACT_EXCEEDED")

        if metrics.estimated_loss_eur >= self.ECONOMIC_LOSS_THRESHOLD:
            reasons.append("ECONOMIC_IMPACT_EXCEEDED")

        if metrics.data_loss_critical:
            reasons.append("CRITICAL_DATA_LOSS")

        is_major = len(reasons) > 0
        window = 4 if is_major else 0

        return ClassificationResult(
            incident_id=metrics.incident_id,
            is_major=is_major,
            trigger_reasons=reasons,
            notification_window_hours=window,
        )
