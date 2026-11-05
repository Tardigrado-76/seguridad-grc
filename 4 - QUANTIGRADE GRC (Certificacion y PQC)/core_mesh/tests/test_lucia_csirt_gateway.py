"""
Tests for LuciaCsirtGateway: CSIRT incident reporting under NIS2 Art. 23 & Guía CCN-STIC 817.
Formats early warnings (24h), notifications (72h), and STIX 2.1 JSON bundles.
"""
import pytest
from core_mesh.operational.lucia_csirt_gateway import (
    LuciaCsirtGateway,
    IncidentNotificationPhase,
    LuciaNotificationPackage,
)


def test_early_warning_24h_generation():
    gateway = LuciaCsirtGateway(csirt_name="CCN-CERT", entity_tax_id="A-28000000")
    incident_data = {
        "incident_id": "INC-2026-001",
        "description": "Ataque de ransomware detectado en segmento perimetral",
        "suspected_unlawful": True,
        "potential_cross_border_impact": False,
        "affected_services": ["Portal Tributario", "API Pagos"],
    }

    pkg = gateway.generate_notification(
        phase=IncidentNotificationPhase.EARLY_WARNING_24H,
        incident_data=incident_data
    )

    assert pkg.phase == IncidentNotificationPhase.EARLY_WARNING_24H
    assert pkg.lucia_format["fase"] == "ALERTA_TEMPRANA_24H"
    assert pkg.lucia_format["entidad_notificadora"]["nif"] == "A-28000000"
    assert pkg.lucia_format["sospecha_acto_ilicito"] is True
    assert len(pkg.merkle_sha256) == 64


def test_incident_notification_72h_severity_and_iocs():
    gateway = LuciaCsirtGateway(csirt_name="CCN-CERT", entity_tax_id="A-28000000")
    incident_data = {
        "incident_id": "INC-2026-001",
        "severity": "CRITICAL",
        "affected_users_count": 25000,
        "ttps": ["T1059", "T1486"],
        "iocs": ["198.51.100.24", "malicious_payload.exe"],
    }

    pkg = gateway.generate_notification(
        phase=IncidentNotificationPhase.INCIDENT_NOTIFICATION_72H,
        incident_data=incident_data
    )

    assert pkg.phase == IncidentNotificationPhase.INCIDENT_NOTIFICATION_72H
    assert pkg.lucia_format["fase"] == "NOTIFICACION_72H"
    assert pkg.lucia_format["evaluacion_inicial"]["severidad"] == "CRITICAL"
    assert len(pkg.lucia_format["evaluacion_inicial"]["ttps"]) == 2


def test_stix_21_bundle_serialization():
    gateway = LuciaCsirtGateway(csirt_name="CCN-CERT", entity_tax_id="A-28000000")
    incident_data = {
        "incident_id": "INC-2026-001",
        "description": "Filtracion de credenciales en servidor VPN",
        "severity": "HIGH",
        "iocs": ["203.0.113.195"],
    }

    bundle = gateway.build_stix_bundle(incident_data)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    
    types = [obj["type"] for obj in bundle["objects"]]
    assert "incident" in types
    assert "indicator" in types
    assert "identity" in types
