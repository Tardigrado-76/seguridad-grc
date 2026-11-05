"""
Tests for LegalFinancialGuard: Actuarial regulatory sanctions and Board liability.
"""
import pytest
from core_mesh.business_execution.legal_financial_guard import (
    LegalFinancialGuard,
    SanctionCalculation,
    ExecutiveLiabilityReport,
)


def test_calculate_dora_sanction():
    guard = LegalFinancialGuard()
    # 50M turnover, Critical severity (100% of statutory max)
    # Statutory max: max(10M, 2% of 50M = 1M) -> 10,000,000 EUR
    calc = guard.calculate_dora_sanction(turnover_eur=50_000_000, severity="CRITICAL")
    assert calc.framework == "DORA"
    assert calc.max_statutory_fine_eur == 10_000_000.0
    assert calc.estimated_fine_eur == 10_000_000.0

    # 1 Billion turnover -> 2% of 1B = 20M > 10M -> statutory max is 20,000,000 EUR
    calc_large = guard.calculate_dora_sanction(turnover_eur=1_000_000_000, severity="MODERATE")
    assert calc_large.max_statutory_fine_eur == 20_000_000.0
    assert calc_large.estimated_fine_eur == 10_000_000.0  # 50% for moderate


def test_calculate_nis2_sanction():
    guard = LegalFinancialGuard()
    # Essential entity with 100M turnover
    calc_essential = guard.calculate_nis2_sanction(
        turnover_eur=100_000_000, entity_type="ESSENTIAL", severity="CRITICAL"
    )
    assert calc_essential.framework == "NIS2"
    assert calc_essential.max_statutory_fine_eur == 10_000_000.0

    # Important entity with 100M turnover: max(7M, 1.4% of 100M = 1.4M) -> 7M
    calc_important = guard.calculate_nis2_sanction(
        turnover_eur=100_000_000, entity_type="IMPORTANT", severity="CRITICAL"
    )
    assert calc_important.max_statutory_fine_eur == 7_000_000.0


def test_calculate_rgpd_sanction():
    guard = LegalFinancialGuard()
    # 500M turnover: max(20M, 4% of 500M = 20M) -> 20,000,000 EUR
    calc = guard.calculate_rgpd_sanction(turnover_eur=500_000_000, severity="HIGH")
    assert calc.framework == "RGPD"
    assert calc.max_statutory_fine_eur == 20_000_000.0
    assert calc.estimated_fine_eur == 15_000_000.0  # 75% for high


def test_evaluate_executive_liability_board():
    guard = LegalFinancialGuard()
    breaches = [
        {"control": "NIS2_GOV_01", "name": "Falta de aprobacion del Consejo de medidas ciber", "severity": "CRITICAL"},
        {"control": "DORA_ICT_02", "name": "Omision de auditoria a proveedor critico", "severity": "HIGH"},
    ]
    report = guard.evaluate_executive_liability(breaches)
    assert report.liability_level in ["ALTA", "MUY_ALTA", "CRITICA"]
    assert report.nis2_art20_disqualification_risk is True
    assert report.criminal_code_31bis_exposure is True
    assert len(report.mitigation_recommendations) >= 2


def test_calculate_remediation_roi():
    guard = LegalFinancialGuard()
    # Remediation cost 50,000 EUR vs potential fine 2,000,000 EUR with 20% inspection probability
    roi = guard.calculate_remediation_roi(remediation_cost_eur=50_000, potential_sanction_eur=2_000_000)
    assert roi.roi_ratio > 1.0
    assert roi.net_savings_eur > 0
