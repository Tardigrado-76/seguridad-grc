#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_pqc_evaluator.py
TDD Suite for PQCEvaluator (Mandato PQC NIST FIPS 203-204).
Tests negative (empty target path -> 0.0% RED) and positive (compliant directory -> 100.0% GREEN).
"""

import sys
import tempfile
from pathlib import Path
import pytest

# Add compliance manager and GCR root to path
comp_mgr = Path(r"e:\PROYECTOS IA\PRODUCTION READY\100\GITHUB\QUANTIGRADE GRC")
gcr_root = Path(r"E:\PROYECTOS IA\GCR")
for p in [comp_mgr, gcr_root]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from src.evaluators.pqc import PQCEvaluator
from src.evaluators.base import RAGStatus, Severity


def test_pqc_evaluator_empty_target_negative():
    """Negative test: an empty directory must result in 0% score and RAGStatus.RED."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        evaluator = PQCEvaluator(tmp_dir, "Test Empty Corp")
        res = evaluator.evaluate()

        assert res.framework_name == "Mandato PQC NIST FIPS 203-204"
        assert res.total_rules == 4
        assert res.passed_rules == 0
        assert res.failed_rules == 4
        assert res.compliance_score == 0.0
        assert res.rag_status == RAGStatus.RED
        assert res.remediation_hours_est > 0
        assert res.estimated_opex_impact_eur > 0

        # Validate rule IDs
        rule_ids = [f.rule_id for f in res.findings]
        assert "PQC-AGIL-001" in rule_ids
        assert "PQC-KEM-002" in rule_ids
        assert "PQC-DSA-003" in rule_ids
        assert "PQC-FIPS-004" in rule_ids


def test_pqc_evaluator_populated_target_positive():
    """Positive test: target path with all PQC assets must yield 100% score and RAGStatus.GREEN."""
    pqc_framework_dir = comp_mgr / "NORMATIVAS" / "Mandato PQC NIST FIPS 203-204"
    evaluator = PQCEvaluator(str(pqc_framework_dir), "Iberia Quantum Corp")
    res = evaluator.evaluate()

    assert res.framework_name == "Mandato PQC NIST FIPS 203-204"
    assert res.total_rules == 4
    assert res.passed_rules == 4
    assert res.failed_rules == 0
    assert res.compliance_score == 100.0
    assert res.rag_status == RAGStatus.GREEN
    assert res.remediation_hours_est == 0.0
    assert res.estimated_opex_impact_eur == 0.0
    assert res.metrics.get("pqc_harvest_now_decrypt_later_mitigated") is True
    assert res.metrics.get("quantum_safety_level") == "NIST_LEVEL_5_HIGH"
