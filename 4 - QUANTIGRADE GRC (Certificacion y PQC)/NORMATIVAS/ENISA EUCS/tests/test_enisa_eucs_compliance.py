"""
Module: test_enisa_eucs_compliance.py
Description: TDD test suite for ENISA EUCS Cloud Cybersecurity Certification Scheme.
Validates:
- EUCS High Requirements: sovereignty, EU data residency, HSM keys, isolated tenant.
- Evaluator: ENISAEUCSEvaluator achieves 100.0% compliance (4/4 controls passed, GREEN).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

compliance_dir = Path("e:/PROYECTOS IA/PRODUCTION READY/100/GITHUB/QUANTIGRADE GRC")
if str(compliance_dir) not in sys.path:
    sys.path.insert(0, str(compliance_dir))

engines_dir = Path(__file__).resolve().parent.parent / "engines"
if str(engines_dir) not in sys.path:
    sys.path.insert(0, str(engines_dir))

from enisa_eucs_cloud_compliance_checker import ENISAEUCSComplianceChecker
from src.evaluators.enisa_eucs import ENISAEUCSEvaluator


def test_enisa_eucs_manifest_audit(tmp_path: Path):
    """Verify ENISA EUCS manifest checker validates EUCS High sovereignty controls."""
    checker = ENISAEUCSComplianceChecker()

    # Create compliant manifest
    manifest_file = tmp_path / "cloud_sovereign_deployment.json"
    manifest_content = {
        "cloud_provider": "EU Sovereign Cloud",
        "controls": [
            "eu_sovereignty_clause",
            "data_residency_eu",
            "hsm_key_management",
            "isolated_tenant_compute",
            "immutable_audit_logs",
        ],
    }
    manifest_file.write_text(json.dumps(manifest_content))

    res = checker.audit_cloud_manifest(manifest_file)
    assert res["is_eucs_high_compliant"] is True
    assert len(res["missing_eucs_high_requirements"]) == 0

    # Create non-compliant manifest
    bad_manifest = tmp_path / "insecure_deployment.json"
    bad_manifest.write_text(json.dumps({"cloud_provider": "Generic Non-EU"}))
    bad_res = checker.audit_cloud_manifest(bad_manifest)
    assert bad_res["is_eucs_high_compliant"] is False
    assert len(bad_res["missing_eucs_high_requirements"]) == 5


def test_enisa_eucs_evaluator_reaches_100_percent(tmp_path):
    """Verify ENISAEUCSEvaluator passes all 4 rules (100.0% GREEN)."""
    (tmp_path / "eucs_sovereign_policy.json").write_text("{}", encoding="utf-8")
    (tmp_path / "kms_hsm_key_management.py").write_text("# HSM", encoding="utf-8")
    (tmp_path / "tenant_isolation_firewall.py").write_text("# Isolation", encoding="utf-8")
    (tmp_path / "iac_drift_checker.py").write_text("# IaC Drift", encoding="utf-8")

    evaluator = ENISAEUCSEvaluator(target_path=str(tmp_path), company_name="Enterprise")
    result = evaluator.evaluate()
    assert result.compliance_score == 100.0
    assert result.passed_rules == 4
    assert result.failed_rules == 0
    assert result.rag_status.value == "GREEN"
