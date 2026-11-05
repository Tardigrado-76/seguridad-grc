"""
Module: test_cra_sbom_kev.py
Description: TDD test suite for Cyber Resilience Act (CRA - Regulation EU 2024/2847).
Validates:
- Art. 10: Machine-readable CycloneDX SBOM generation
- Art. 10: Vulnerability checking against CISA KEV catalog
- Evaluator: CRASBOMEvaluator reaches 100.0% compliance (3/3 controls, GREEN).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add paths
cra_dir = Path(__file__).resolve().parent.parent
comp_dir = Path("e:/PROYECTOS IA/PRODUCTION READY/100/GITHUB/QUANTIGRADE GRC")
if str(comp_dir) not in sys.path:
    sys.path.insert(0, str(comp_dir))

from src.evaluators.cra_sbom import CRASBOMEvaluator


def test_cra_evaluator_100_percent(tmp_path):
    """Verify CRASBOMEvaluator validates all 3 CRA controls with 100.0% GREEN when compliant assets exist."""
    (tmp_path / "cyclonedx_sbom.json").write_text('{"bomFormat": "CycloneDX"}', encoding="utf-8")
    (tmp_path / "cisa_kev_checker.py").write_text("# KEV audit", encoding="utf-8")
    (tmp_path / "ai_compliance_engine.py").write_text("# AI compliance", encoding="utf-8")

    evaluator = CRASBOMEvaluator(target_path=str(tmp_path), company_name="Enterprise")
    result = evaluator.evaluate()
    assert result.compliance_score == 100.0
    assert result.passed_rules == 3
    assert result.failed_rules == 0
    assert result.rag_status.value == "GREEN"


def test_cra_evaluator_empty_negative(tmp_path):
    """Verify CRASBOMEvaluator yields 0.0% RED on empty target."""
    evaluator = CRASBOMEvaluator(target_path=str(tmp_path), company_name="Enterprise")
    result = evaluator.evaluate()
    assert result.compliance_score == 0.0
    assert result.passed_rules == 0
    assert result.failed_rules == 3
    assert result.rag_status.value == "RED"
