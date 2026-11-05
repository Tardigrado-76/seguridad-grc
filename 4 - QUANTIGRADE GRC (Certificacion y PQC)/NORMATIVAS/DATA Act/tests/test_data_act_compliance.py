#!/usr/bin/env python3
"""
test_data_act_compliance.py - TDD & Verification Suite for EU Data Act Compliance.
Verifies B2B FRAND Sharing Broker, Cloud Switching & Zero Egress Fees, Smart Contract Guard,
and DataActEvaluator scoring 100.0% GREEN.
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

from data_act import DataActEvaluator
from data_act_b2b_sharing_broker import DataActB2BSharingBroker
from data_act_cloud_switching_orchestrator import DataActCloudSwitchingOrchestrator
from data_act_smart_contract_guard import DataActSmartContractGuard
from src.evaluators.base import RAGStatus


def test_data_act_b2b_sharing_broker(tmp_path: Path) -> None:
    """Verifies Arts. 3-5 & 8-13 B2B data sharing under FRAND terms."""
    broker = DataActB2BSharingBroker(data_holder_id="HOLDER-EU-01", output_dir=str(tmp_path))
    ag = broker.create_sharing_agreement(
        user_or_business_id="CLIENT-ES-001",
        third_party_recipient="PARTNER-TECH-DE",
        dataset_description="Industrial vehicle IoT telemetry",
        compensation_eur=100.0,
        is_sme_recipient=True,
    )

    assert ag["agreement_id"].startswith("DA-B2B-")
    assert ag["frand_compliance"]["compliant"] is True
    assert ag["trade_secret_protection"]["compliant"] is True
    assert "agreement_sha256" in ag


def test_data_act_cloud_switching_orchestrator(tmp_path: Path) -> None:
    """Verifies Arts. 23-29 Cloud Switching Portability & Abolition of Egress Fees."""
    orchestrator = DataActCloudSwitchingOrchestrator(provider_id="SOV-CLOUD-01", output_dir=str(tmp_path))
    plan = orchestrator.plan_cloud_migration(
        customer_id="CORP-CLIENT-99",
        destination_provider="SOV-CLOUD-02",
        data_volume_gb=5000.0,
        export_format="PARQUET",
        egress_fee_eur=0.0,
        transition_period_days=30,
    )

    assert plan["migration_id"].startswith("CSW-")
    assert plan["zero_egress_compliance"]["compliant"] is True
    assert plan["portability_compliance"]["compliant"] is True
    assert plan["sla_compliance"]["compliant"] is True
    assert "plan_sha256" in plan


def test_data_act_smart_contract_guard() -> None:
    """Verifies Art. 36 Smart Contract Essential Requirements (kill-switch, access control)."""
    guard = DataActSmartContractGuard()
    res = guard.audit_contract_specification(
        contract_id="SC-DATA-EXCHANGE-2026",
        features=["Pauseable", "AccessControl", "AuditTrail"],
        has_emergency_stop=True,
        has_access_control=True,
        protects_trade_secrets=True,
    )

    assert res["conformity_declaration"] is True
    assert res["compliance_score"] == 100.0
    assert res["checks"]["safe_termination"]["passed"] is True
    assert "audit_seal_sha256" in res


def test_data_act_evaluator_scores_100_percent() -> None:
    """Verifies DataActEvaluator produces a 100.0% compliance score with GREEN status."""
    evaluator = DataActEvaluator(target_path=str(BASE_DIR), company_name="DataCorp S.A.")
    result = evaluator.evaluate()

    assert result.framework_name == "DATA_ACT"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert len(result.findings) == 4
    for finding in result.findings:
        assert finding.passed is True
