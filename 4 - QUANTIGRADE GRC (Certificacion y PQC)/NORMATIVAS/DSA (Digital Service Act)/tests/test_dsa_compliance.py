#!/usr/bin/env python3
"""
test_dsa_compliance.py - TDD & Verification Suite for Digital Services Act (DSA) Compliance.
Verifies Notice & Action Engine, Transparency Reporting & Recommender Audit, Dark Patterns Guard,
and DSAEvaluator scoring 100.0% GREEN.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add paths
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "engines"))
sys.path.insert(0, str(BASE_DIR / "evaluators"))

CENTRAL_MGR = Path("e:/PROYECTOS IA/PRODUCTION READY/100/GITHUB/QUANTIGRADE GRC")
if CENTRAL_MGR.exists():
    sys.path.insert(0, str(CENTRAL_MGR))

from dsa import DSAEvaluator
from dsa_dark_patterns_and_minors_guard import DSADarkPatternsAndMinorsGuard
from dsa_illegal_content_moderation_engine import DSAIllegalContentModerationEngine
from dsa_transparency_reporting_generator import DSATransparencyReportingGenerator
from src.evaluators.base import RAGStatus


def test_dsa_notice_and_action_engine(tmp_path: Path) -> None:
    """Verifies Arts. 16, 17, 20 Notice & Action, Statement of Reasons, and Internal Appeals."""
    engine = DSAIllegalContentModerationEngine(platform_id="PLATFORM-EU-TEST", output_dir=str(tmp_path))
    notice = engine.submit_notice(
        notifier_email="flagger@safeinternet.eu",
        content_id="ITEM-10029",
        legal_basis="Child safety violation / CSAM",
        explanation="Urgent notice of illegal content",
        exact_location_url="https://platform.eu/media/10029",
    )

    assert notice["notice_id"].startswith("DSA-NOT-")
    assert notice["dsa_art16_compliant"] is True

    # Issue Statement of Reasons
    sor = engine.issue_statement_of_reasons(
        notice_id=notice["notice_id"],
        decision_type="CONTENT_REMOVAL",
        legal_or_contractual_ground="DSA Art. 16 valid notice confirmed illegal content",
        facts_and_circumstances="Material definitively identified and removed",
        automated_decision=False,
    )
    assert sor["statement_of_reasons_id"].startswith("DSA-SOR-")
    assert sor["commission_transparency_database_ready"] is True

    # Appeal handling
    appeal = engine.process_internal_complaint(
        statement_of_reasons_id=sor["statement_of_reasons_id"],
        complainant_id="USER-771",
        reasons_for_appeal="Content was parody and did not violate law",
    )
    assert appeal["human_in_the_loop_mandatory"] is True
    assert appeal["dsa_art20_compliant"] is True


def test_dsa_transparency_reporting_and_recommenders(tmp_path: Path) -> None:
    """Verifies Arts. 15, 24, 27 Transparency Reports and Recommender System Parameters."""
    generator = DSATransparencyReportingGenerator(platform_id="PLATFORM-EU-TEST", output_dir=str(tmp_path))
    report = generator.generate_periodic_transparency_report(
        reporting_period="2026-H1",
        total_orders_received=2,
        total_notices_received=150,
        total_notices_actioned=140,
        avg_processing_hours=4.2,
        own_initiative_moderation_count=50,
        complaints_received=10,
        complaints_reversed=1,
    )
    assert report["commission_transparency_template_conformity"] is True
    assert report["metrics"]["action_rate_percentage"] > 90.0

    # Recommender system audit
    compliant, audit = generator.audit_recommender_system(
        recommender_id="MAIN-FEED-DISCOVERY",
        ranking_factors=["engagement", "freshness", "relevance"],
        has_user_adjustable_parameters=True,
        offers_non_profiling_alternative=True,
    )
    assert compliant is True
    assert audit["status"] == "APPROVED"


def test_dsa_dark_patterns_and_minors_guard() -> None:
    """Verifies Arts. 25 & 28 Prohibition of dark patterns and minor safety."""
    guard = DSADarkPatternsAndMinorsGuard()

    # Clean UI check
    clean_ui, ui_rep = guard.audit_ui_interface_design([
        {"name": "ConsentModal", "pattern_detected": "BALANCED_CHOICE_SYMMETRIC"},
        {"name": "CancelButton", "pattern_detected": "DIRECT_CLEAR_TEXT"},
    ])
    assert clean_ui is True
    assert ui_rep["status"] == "APPROVED_CLEAN_UI"

    # Minor protection audit
    minor_safe, minor_rep = guard.audit_minors_protection_policy(
        minor_access_allowed=True,
        profiling_ads_enabled_for_minors=False,
        high_privacy_by_default=True,
    )
    assert minor_safe is True
    assert minor_rep["status"] == "MINOR_SAFETY_VERIFIED"


def test_dsa_evaluator_scores_100_percent() -> None:
    """Verifies DSAEvaluator produces a 100.0% compliance score with GREEN status."""
    evaluator = DSAEvaluator(target_path=str(BASE_DIR), company_name="PlatformCorp S.A.")
    result = evaluator.evaluate()

    assert result.framework_name == "DSA"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert len(result.findings) == 4
    for finding in result.findings:
        assert finding.passed is True
