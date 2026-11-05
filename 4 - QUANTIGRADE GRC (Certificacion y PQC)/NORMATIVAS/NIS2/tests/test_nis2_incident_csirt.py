"""
Module: test_nis2_incident_csirt.py
Description: TDD test suite for NIS2 Directive (EU 2022/2555).
Validates:
- Art. 21 & 23: Early warning (24h) and incident notification (72h) to CSIRT/NCA
- Evaluator: NIS2Evaluator reaches 100.0% compliance (4/4 controls, GREEN).
"""

from __future__ import annotations

import sys
from pathlib import Path

comp_dir = Path("e:/PROYECTOS IA/PRODUCTION READY/100/GITHUB/QUANTIGRADE GRC")
if str(comp_dir) not in sys.path:
    sys.path.insert(0, str(comp_dir))

from src.evaluators.nis2 import NIS2Evaluator


def test_nis2_evaluator_100_percent(tmp_path: Path):
    """Verify NIS2Evaluator validates all 4 statutory controls with 100.0% GREEN."""
    (tmp_path / "mfa_auth_policy.md").write_text("MFA Policy")
    (tmp_path / "supply_chain_sbom.json").write_text("{}")
    (tmp_path / "csirt_incident_reporting.md").write_text("CSIRT Notification 24h")
    (tmp_path / "backup_recovery_plan.md").write_text("Immutable Backups")

    evaluator = NIS2Evaluator(target_path=str(tmp_path), company_name="Enterprise")
    result = evaluator.evaluate()
    assert result.compliance_score == 100.0
    assert result.passed_rules == 4
    assert result.failed_rules == 0
    assert result.rag_status.value == "GREEN"
