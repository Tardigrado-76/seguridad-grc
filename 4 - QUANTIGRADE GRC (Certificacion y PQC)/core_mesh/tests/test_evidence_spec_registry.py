"""
Test suite for EvidenceSpecRegistry and Remediation Engine.
Validates 19 framework specifications, 6 regulatory families,
read-only Zero-Touch preflight inspection, and framework-specific remediation.
"""

import os
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
from core_mesh.operational.evidence_spec_registry import (
    EvidenceSpecRegistry,
    FrameworkEvidenceSpec
)


def test_registry_covers_all_25_frameworks():
    specs = EvidenceSpecRegistry.get_all_specs()
    assert len(specs) == 25
    
    # Verify all expected framework keys exist
    expected_keys = [
        "CRA", "DATA Act", "DORA", "DSA (Digital Service Act)", "eIDAS 2.0",
        "ENISA EUCS", "ENS", "EU AI Act", "ISO 27001 - SOC2", "NIS2",
        "OWASP LLM 2025", "RGPD - LOPDGDD", "Ciberresiliencia Financiera en España",
        "Corporate Defense y Prevención Penal", "Gobernanza de IA en España (AESIA)",
        "Ley de Secretos Empresariales", "Ley General de Telecomunicaciones (LGTel)",
        "LSSI-CE (Servicios Sociedad Información y Cookies)", "Protección de Infraestructuras Críticas (LPIC)",
        "Mandato PQC NIST FIPS 203-204", "DGAM", "ITAR - EAR", "MCCE",
        "ISA-IEC 62443 Ciberseguridad Industrial OT - IoT", "DPP & Trazabilidad Aduanera UE"
    ]
    for k in expected_keys:
        assert k in specs, f"Framework {k} missing from registry"
        spec = specs[k]
        assert isinstance(spec, FrameworkEvidenceSpec)
        assert len(spec.expected_artifacts) > 0
        assert len(spec.legal_citations) > 0
        assert spec.family is not None


def test_preflight_check_zero_touch_read_only():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # Empty directory check
        result = EvidenceSpecRegistry.preflight_check("DORA", tmp_path)
        
        assert result["framework"] == "DORA"
        assert result["is_compliant"] is False
        assert result["missing_count"] > 0
        assert result["found_count"] == 0
        
        # Verify Zero-Touch: no files created by the check
        assert list(tmp_path.iterdir()) == []


def test_preflight_check_detects_evidence_files():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # Create DORA evidence structure
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "dora_bcp_drp_policy.md").write_text("# DORA BCP Policy", encoding="utf-8")
        
        engines_dir = tmp_path / "engines"
        engines_dir.mkdir()
        (engines_dir / "dora_incident_classifier.py").write_text("# Classifier", encoding="utf-8")

        result = EvidenceSpecRegistry.preflight_check("DORA", tmp_path)
        assert result["found_count"] >= 2
        # Check specific artifact status
        found_names = [a["name"] for a in result["artifacts"] if a["found"]]
        assert any("bcp" in name.lower() or "incident" in name.lower() for name in found_names)


def test_remediate_incident_creates_target_artifact():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # Remediation creates missing policy or engine
        remediation_res = EvidenceSpecRegistry.remediate_incident(
            framework_key="DORA",
            target_path=tmp_path,
            artifact_pattern="dora_bcp_drp_policy.md",
            company_name="Test Corp S.A."
        )
        assert remediation_res["success"] is True
        created_file = Path(remediation_res["created_path"])
        assert created_file.exists()
        content = created_file.read_text(encoding="utf-8")
        assert "Test Corp S.A." in content or "DORA" in content
