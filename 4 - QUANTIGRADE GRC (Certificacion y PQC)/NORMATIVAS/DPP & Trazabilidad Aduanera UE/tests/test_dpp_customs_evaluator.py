#!/usr/bin/env python3
"""
TDD Suite for DPPCustomsEvaluator (EU Digital Product Passport & Customs Data Hub).
Validates genuine evidence verification:
- Negative test: target without evidences -> RED status, 0% score.
- Positive test: target with valid framework evidences -> GREEN status, 100% score.
"""

import sys
import tempfile
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
EVAL_DIR = CURRENT_DIR.parent / "evaluators"
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from dpp_customs import DPPCustomsEvaluator
from src.evaluators.base import RAGStatus


def test_dpp_customs_detects_missing_evidences():
    """Negative test: an empty directory must trigger 0.0% compliance and RED status."""
    with tempfile.TemporaryDirectory() as empty_dir:
        evaluator = DPPCustomsEvaluator(target_path=empty_dir, company_name="NonCompliantCustomsOperator")
        result = evaluator.evaluate()

        assert result.framework_name == "DPP_TRAZABILIDAD_ADUANERA_UE"
        assert result.compliance_score == 0.0
        assert result.rag_status == RAGStatus.RED
        assert result.total_rules == 4
        assert result.passed_rules == 0
        assert result.failed_rules == 4
        for finding in result.findings:
            assert finding.passed is False

def test_dpp_customs_validates_complete_evidences():
    """Positive test: target path with complete framework implementations must pass 100% GREEN."""
    evaluator = DPPCustomsEvaluator(target_path=str(CURRENT_DIR.parent), company_name="CompliantLogisticsHub S.A.")
    result = evaluator.evaluate()

    assert result.framework_name == "DPP_TRAZABILIDAD_ADUANERA_UE"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert result.total_rules == 4
    assert result.passed_rules == 4
    assert result.failed_rules == 0
    for finding in result.findings:
        assert finding.passed is True
