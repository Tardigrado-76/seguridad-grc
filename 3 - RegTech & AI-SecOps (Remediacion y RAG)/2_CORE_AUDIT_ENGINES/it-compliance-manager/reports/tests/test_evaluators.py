#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for framework evaluators using synthetic target directories."""

from pathlib import Path

from src.evaluators.dora import DORAEvaluator
from src.evaluators.nis2 import NIS2Evaluator
from src.evaluators.ens_high import ENSHighEvaluator
from src.evaluators.gdpr_toms import GDPRTOMsEvaluator
from src.evaluators.cra_sbom import CRASBOMEvaluator
from src.evaluators.base import RAGStatus


def _write(target: Path, name: str, content: str = "contenido de politica de seguridad"):
    f = target / name
    f.write_text(content, encoding="utf-8")


def test_dora_full_pass(tmp_path):
    # Evidencias que cubren las 5 reglas DORA
    _write(tmp_path, "dora_ict_risk_policy.md")
    _write(tmp_path, "dora_incident_classifier.py")
    _write(tmp_path, "third_party_roi_register.json")
    _write(tmp_path, "chaos_tlpt_failover.ps1")
    _write(tmp_path, "merkle_log_verifier.py")

    res = DORAEvaluator(str(tmp_path), "TESTCO").evaluate()

    assert res.framework_name == "DORA"
    assert res.total_rules == 5
    assert res.passed_rules == 5
    assert res.compliance_score == 100.0
    assert res.rag_status == RAGStatus.GREEN


def test_dora_empty_dir_scores_zero(tmp_path):
    _write(tmp_path, "readme.txt")

    res = DORAEvaluator(str(tmp_path), "TESTCO").evaluate()

    assert res.total_rules == 5
    assert res.passed_rules == 0
    assert res.compliance_score == 0.0
    assert res.rag_status == RAGStatus.RED


def test_nis2_returns_result(tmp_path):
    _write(tmp_path, "nis2_incident_notification_24h.md")

    res = NIS2Evaluator(str(tmp_path), "TESTCO").evaluate()

    assert res.framework_name == "NIS2"
    assert res.total_rules > 0
    assert 0.0 <= res.compliance_score <= 100.0
    assert res.passed_rules + res.failed_rules == res.total_rules


def test_ens_alto_returns_result(tmp_path):
    res = ENSHighEvaluator(str(tmp_path), "TESTCO").evaluate()

    assert res.framework_name == "ENS_ALTO"
    assert res.total_rules > 0


def test_gdpr_returns_result(tmp_path):
    _write(tmp_path, "gdpr_toms.md")

    res = GDPRTOMsEvaluator(str(tmp_path), "TESTCO").evaluate()

    assert res.framework_name == "GDPR"
    assert res.total_rules > 0


def test_cra_returns_result(tmp_path):
    _write(tmp_path, "sbom_cyclonedx.json")

    res = CRASBOMEvaluator(str(tmp_path), "TESTCO").evaluate()

    assert res.framework_name == "CRA"
    assert res.total_rules > 0


def test_findings_carry_remediation_and_mappings(tmp_path):
    res = DORAEvaluator(str(tmp_path), "TESTCO").evaluate()

    for finding in res.findings:
        assert finding.rule_id
        assert finding.title
        assert finding.remediation_guidance
        assert finding.severity.value in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


if __name__ == '__main__':
    # Production entry point
    pass
