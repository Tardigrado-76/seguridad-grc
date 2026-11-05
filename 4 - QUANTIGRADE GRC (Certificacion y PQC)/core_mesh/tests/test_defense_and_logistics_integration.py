#!/usr/bin/env python3
"""
test_defense_and_logistics_integration.py
Test suite validating end-to-end integration of the 5 new strategic frameworks:
1. DGAM (PECAL 2110/2210 & REDGAM)
2. ITAR - EAR (USML / CCL / Dual-Use UE 2021/821)
3. MCCE (Ciberdefensa Militar & STANAG 4774/4778)
4. ISA-IEC 62443 (Ciberseguridad Industrial OT/IoT Zonas & Conductos)
5. DPP & Trazabilidad Aduanera UE (ESPR & Customs Data Hub)
"""

import sys
from pathlib import Path

GCR_ROOT = Path(__file__).resolve().parent.parent.parent
if str(GCR_ROOT) not in sys.path:
    sys.path.insert(0, str(GCR_ROOT))

from src.evaluators.base import RAGStatus
from src.evaluators.dgam import DGAMEvaluator
from src.evaluators.dpp_customs import DPPCustomsEvaluator
from src.evaluators.isa_iec_62443 import ISAIEC62443Evaluator
from src.evaluators.itar_ear import ITAREAREvaluator
from src.evaluators.mcce import MCCEEvaluator

from core_mesh.business_execution.financial_impact_quantifier import (
    FinancialImpactQuantifier,
)
from core_mesh.operational.evidence_spec_registry import EvidenceSpecRegistry


def test_dgam_evaluator_direct_instantiation():
    dgam_path = GCR_ROOT / "NORMATIVAS" / "OTAN" / "DGAM"
    evaluator = DGAMEvaluator(target_path=str(dgam_path), company_name="Navantia & Indra Systems")
    result = evaluator.evaluate()
    assert result.framework_name == "DGAM_PECAL_DEFENSA_ES"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert result.total_rules == 4
    assert result.passed_rules == 4


def test_itar_ear_evaluator_direct_instantiation():
    itar_path = GCR_ROOT / "NORMATIVAS" / "OTAN" / "ITAR - EAR"
    evaluator = ITAREAREvaluator(target_path=str(itar_path), company_name="Airbus Defense & Space")
    result = evaluator.evaluate()
    assert result.framework_name == "ITAR_EAR_DUAL_USE_EXPORT_CONTROL"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert result.total_rules == 4
    assert result.passed_rules == 4


def test_mcce_evaluator_direct_instantiation():
    mcce_path = GCR_ROOT / "NORMATIVAS" / "OTAN" / "MCCE"
    evaluator = MCCEEvaluator(target_path=str(mcce_path), company_name="MCCE Joint Cyber Command")
    result = evaluator.evaluate()
    assert result.framework_name == "MCCE_CIBERDEFENSA_MILITAR_OTAN"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert result.total_rules == 4
    assert result.passed_rules == 4


def test_isa_iec_62443_evaluator_direct_instantiation():
    iec_path = GCR_ROOT / "NORMATIVAS" / "ISA-IEC 62443 Ciberseguridad Industrial OT - IoT"
    evaluator = ISAIEC62443Evaluator(target_path=str(iec_path), company_name="Puertos del Estado & AENA")
    result = evaluator.evaluate()
    assert result.framework_name == "ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert result.total_rules == 4
    assert result.passed_rules == 4


def test_dpp_customs_evaluator_direct_instantiation():
    dpp_path = GCR_ROOT / "NORMATIVAS" / "DPP & Trazabilidad Aduanera UE"
    evaluator = DPPCustomsEvaluator(target_path=str(dpp_path), company_name="Global 3PL Customs Operator")
    result = evaluator.evaluate()
    assert result.framework_name == "DPP_TRAZABILIDAD_ADUANERA_UE"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert result.total_rules == 4
    assert result.passed_rules == 4


def test_financial_exposure_models_for_new_sectors():
    turnover = 100_000_000.0
    
    # DGAM
    exp_dgam = FinancialImpactQuantifier.calculate_exposure("DGAM", turnover, 100.0)
    assert exp_dgam["max_potential_fine_eur"] == 20_000_000.0
    assert exp_dgam["residual_risk_eur"] == 0.0

    # ITAR - EAR
    exp_itar = FinancialImpactQuantifier.calculate_exposure("ITAR_EAR", turnover, 50.0)
    assert exp_itar["max_potential_fine_eur"] == 25_000_000.0
    assert exp_itar["residual_risk_eur"] == 12_500_000.0

    # MCCE
    exp_mcce = FinancialImpactQuantifier.calculate_exposure("MCCE", turnover, 100.0)
    assert exp_mcce["max_potential_fine_eur"] == 30_000_000.0

    # ISA_IEC_62443
    exp_iec = FinancialImpactQuantifier.calculate_exposure("ISA_IEC_62443", turnover, 100.0)
    assert exp_iec["max_potential_fine_eur"] == 15_000_000.0

    # DPP_CUSTOMS
    exp_dpp = FinancialImpactQuantifier.calculate_exposure("DPP_CUSTOMS", turnover, 100.0)
    assert exp_dpp["max_potential_fine_eur"] == 10_000_000.0


def test_preflight_check_discovers_all_5_framework_artifacts():
    mappings = [
        ("DGAM", GCR_ROOT / "NORMATIVAS" / "OTAN" / "DGAM"),
        ("ITAR - EAR", GCR_ROOT / "NORMATIVAS" / "OTAN" / "ITAR - EAR"),
        ("MCCE", GCR_ROOT / "NORMATIVAS" / "OTAN" / "MCCE"),
        ("ISA-IEC 62443 Ciberseguridad Industrial OT - IoT", GCR_ROOT / "NORMATIVAS" / "ISA-IEC 62443 Ciberseguridad Industrial OT - IoT"),
        ("DPP & Trazabilidad Aduanera UE", GCR_ROOT / "NORMATIVAS" / "DPP & Trazabilidad Aduanera UE")
    ]
    for key, path in mappings:
        res = EvidenceSpecRegistry.preflight_check(key, path)
        assert res["is_compliant"] is True
        assert res["missing_count"] == 0
        assert res["found_count"] > 0
        assert res["compliance_ratio"] == 100.0
