#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_owasp_llm_evaluator.py
TDD Suite for OWASPLLMEvaluator verifying negative (empty dir -> 0% RED) and positive (populated dir -> 100% GREEN).
"""

import sys
import tempfile
from pathlib import Path
import pytest

comp_mgr = Path(r"e:\PROYECTOS IA\PRODUCTION READY\100\GITHUB\QUANTIGRADE GRC")
gcr_root = Path(r"E:\PROYECTOS IA\GCR")
for p in [comp_mgr, gcr_root]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from src.evaluators.owasp_llm import OWASPLLMEvaluator
from src.evaluators.base import RAGStatus, Severity


def test_owasp_llm_evaluator_empty_target_negative():
    """Negative test: empty dir must produce 0.0% score and RAGStatus.RED."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        evaluator = OWASPLLMEvaluator(tmp_dir, "Test Empty Corp")
        res = evaluator.evaluate()

        assert res.framework_name == "OWASP LLM 2025"
        assert res.total_rules == 4
        assert res.passed_rules == 0
        assert res.failed_rules == 4
        assert res.compliance_score == 0.0
        assert res.rag_status == RAGStatus.RED

        rule_ids = [f.rule_id for f in res.findings]
        assert "OWASP-LLM-001" in rule_ids
        assert "OWASP-LLM-002" in rule_ids
        assert "OWASP-LLM-003" in rule_ids
        assert "OWASP-LLM-004" in rule_ids


def test_owasp_llm_evaluator_populated_target_positive():
    """Positive test: target path with all OWASP LLM assets yields 100.0% score and RAGStatus.GREEN."""
    owasp_dir = comp_mgr / "NORMATIVAS" / "OWASP LLM 2025"
    evaluator = OWASPLLMEvaluator(str(owasp_dir), "Iberia AI Corp")
    res = evaluator.evaluate()

    assert res.framework_name == "OWASP LLM 2025"
    assert res.total_rules == 4
    assert res.passed_rules == 4
    assert res.failed_rules == 0
    assert res.compliance_score == 100.0
    assert res.rag_status == RAGStatus.GREEN
    assert res.metrics["owasp_llm_top10_status"] == "HARDENED"
