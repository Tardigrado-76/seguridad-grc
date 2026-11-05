"""
Security Audit Suite: test_phase11.py
Validates real DORA Art. 18 Major ICT Incident Classification per EBA/RTS/2024/02 thresholds.
"""

from pathlib import Path
import pytest
import sys

_AUDIT_DIR = str(Path(__file__).resolve().parent.parent)
if _AUDIT_DIR not in sys.path:
    sys.path.insert(0, _AUDIT_DIR)

from dora_incident_classifier import DORAIncidentClassifier, IncidentMetrics


def test_dora_major_incident_classification():
    """Verify incident exceeding critical client and downtime thresholds triggers MAJOR classification."""
    metrics = IncidentMetrics(
        incident_id="INC-2026-001",
        title="Core Gateway Payment Outage",
        service_name="Instant Payments Settlement",
        is_critical_function=True,
        affected_clients_count=150_000,
        total_clients_base=1_000_000,
        downtime_hours=3.5,
        economic_loss_eur=250_000.0,
        geographical_spread_countries=3,
        data_loss_integrity_compromised=False,
        confidentiality_breach=False,
        reputational_impact_high=True
    )

    classifier = DORAIncidentClassifier(metrics)
    report = classifier.evaluate()

    assert report.is_major is True
    assert report.mandatory_nca_notification is True
    assert report.notification_deadline_hours == 2.0
    assert report.criteria_triggered_count >= 2


def test_dora_minor_incident_classification():
    """Verify low-impact incident on non-critical service does not trigger MAJOR classification."""
    metrics = IncidentMetrics(
        incident_id="INC-2026-002",
        title="Internal Documentation Wiki Maintenance Lag",
        service_name="Internal Docs",
        is_critical_function=False,
        affected_clients_count=50,
        total_clients_base=1_000_000,
        downtime_hours=0.5,
        economic_loss_eur=500.0,
        geographical_spread_countries=1,
        data_loss_integrity_compromised=False,
        confidentiality_breach=False,
        reputational_impact_high=False
    )

    classifier = DORAIncidentClassifier(metrics)
    report = classifier.evaluate()

    assert report.is_major is False
    assert report.mandatory_nca_notification is False
    assert report.criteria_triggered_count == 0
