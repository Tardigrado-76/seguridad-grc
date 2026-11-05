#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TDD Suite for AESIAGovernanceEvaluator (Gobernanza de IA en España (AESIA)).
Validates genuine evidence verification:
- Negative test: target without evidences -> RED status, 0% score.
- Positive test: target with valid framework evidences -> GREEN status, 100% score.
"""

import sys
import tempfile
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
EVAL_DIR = CURRENT_DIR.parent / "evaluators"
sys.path.insert(0, str(EVAL_DIR))

from aesia_ia import AESIAGovernanceEvaluator
from src.evaluators.base import RAGStatus

def test_aesia_ia_detects_missing_evidences():
    """Negative test: an empty directory must trigger 0.0% compliance and RED status."""
    with tempfile.TemporaryDirectory() as empty_dir:
        evaluator = AESIAGovernanceEvaluator(target_path=empty_dir, company_name="NonCompliantCorp")
        result = evaluator.evaluate()

        assert result.framework_name == "AESIA_GOBERNANZA_IA_ES"
        assert result.compliance_score == 0.0
        assert result.rag_status == RAGStatus.RED
        assert result.total_rules == 4
        assert result.passed_rules == 0
        assert result.failed_rules == 4
        for finding in result.findings:
            assert finding.passed is False

def test_aesia_ia_validates_complete_evidences():
    """Positive test: target path with complete framework implementations must pass 100% GREEN."""
    evaluator = AESIAGovernanceEvaluator(target_path=str(CURRENT_DIR.parent), company_name="CompliantIberia S.A.")
    result = evaluator.evaluate()

    assert result.framework_name == "AESIA_GOBERNANZA_IA_ES"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert result.total_rules == 4
    assert result.passed_rules == 4
    assert result.failed_rules == 0
    for finding in result.findings:
        assert finding.passed is True
