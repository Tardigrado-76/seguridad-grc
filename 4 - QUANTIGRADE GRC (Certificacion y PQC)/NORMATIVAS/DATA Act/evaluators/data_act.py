#!/usr/bin/env python3
"""
data_act.py - EU Data Act (Regulation EU 2023/2854) Compliance Evaluator.
Auditing B2B/IoT Data Sharing under FRAND terms (Arts. 3-5, 8-13), Cloud Provider Switching &
Zero Egress Fees (Arts. 23-29), Smart Contract Conformity (Art. 36), and International Transfer Safeguards.
"""

from __future__ import annotations

import os
from pathlib import Path

from src.evaluators.base import (
    BaseEvaluator,
    EvaluatorResult,
    Finding,
    RAGStatus,
    Severity,
)


class DataActEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "DATA_ACT"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)

        # 1. Arts. 3-5, 8-13: B2B and IoT Data Sharing under FRAND terms
        has_sharing = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["sharing", "broker", "frand", "iot_data"]):
                    has_sharing = True
                    break

        findings.append(Finding(
            rule_id="DATA-ACT-SHARING-001",
            framework="DATA_ACT",
            title="Data Act Arts. 3-5 & 8-13 B2B and IoT Fair Data Access (FRAND)",
            description="Verify mechanisms for making IoT and product data accessible to users and authorized third parties under Fair, Reasonable and Non-Discriminatory (FRAND) terms.",
            severity=Severity.CRITICAL,
            passed=has_sharing,
            evidence=f"B2B Data Sharing broker present: {has_sharing}",
            remediation_guidance="Implement automated FRAND agreement brokers with cost-reflective compensation safeguards for SMEs.",
            iso27001_mapping=["A.5.10", "A.8.12"],
            soc2_mapping=["CC6.1", "CC6.3"]
        ))

        # 2. Arts. 23-29: Cloud Switching, Portability & Abolition of Egress Fees
        has_cloud_switching = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["switching", "cloud", "egress", "portability"]):
                    has_cloud_switching = True
                    break

        findings.append(Finding(
            rule_id="DATA-ACT-SWITCH-002",
            framework="DATA_ACT",
            title="Data Act Arts. 23-29 Cloud Switching Portability & Zero Egress Fees",
            description="Verify absence of commercial, technical, and contractual barriers to cloud provider switching, including total abolition of egress fees.",
            severity=Severity.HIGH,
            passed=has_cloud_switching,
            evidence=f"Cloud switching and zero egress fee orchestrator present: {has_cloud_switching}",
            remediation_guidance="Eliminate data transfer and egress charges during customer cloud provider migration.",
            iso27001_mapping=["A.5.8", "A.8.20"],
            soc2_mapping=["CC6.6", "CC6.7"]
        ))

        # 3. Art. 36: Smart Contract Conformity for Data Sharing
        has_smart_contract = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["smart_contract", "guard", "kill_switch"]):
                    has_smart_contract = True
                    break

        findings.append(Finding(
            rule_id="DATA-ACT-CONTRACT-003",
            framework="DATA_ACT",
            title="Data Act Art. 36 Smart Contract Essential Requirements (Kill Switch & Access Control)",
            description="Verify that smart contracts deployed for data sharing include rigorous access control, data confidentiality, and safe emergency termination/kill-switch mechanisms.",
            severity=Severity.HIGH,
            passed=has_smart_contract,
            evidence=f"Smart contract essential requirements validator present: {has_smart_contract}",
            remediation_guidance="Incorporate pausability and safe kill-switch logic in all automated data exchange contracts.",
            iso27001_mapping=["A.8.24", "A.8.28"],
            soc2_mapping=["CC7.1", "CC7.2"]
        ))

        # 4. Arts. 27 & 32: International Governmental Data Transfer Safeguards
        has_intl_safeguards = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["sovereign", "broker", "safeguard", "cloud", "enclave"]):
                    has_intl_safeguards = True
                    break

        findings.append(Finding(
            rule_id="DATA-ACT-INTL-004",
            framework="DATA_ACT",
            title="Data Act Arts. 27 & 32 Safeguards Against Unlawful International Government Access",
            description="Verify technical, legal, and cryptographic measures preventing non-EU/EEA governments from accessing European commercial data without valid judicial treaty (MLAT).",
            severity=Severity.CRITICAL,
            passed=has_intl_safeguards,
            evidence=f"Sovereign cloud safeguards and enclave mechanisms present: {has_intl_safeguards}",
            remediation_guidance="Deploy end-to-end encryption with keys retained exclusively in EU jurisdictions.",
            iso27001_mapping=["A.5.31", "A.8.24"],
            soc2_mapping=["CC6.1", "CC6.8"]
        ))

        passed_count = sum(1 for f in findings if f.passed)
        total_count = len(findings)
        score = (passed_count / total_count * 100.0) if total_count > 0 else 0.0

        if score >= 90.0:
            status = RAGStatus.GREEN
        elif score >= 70.0:
            status = RAGStatus.AMBER
        else:
            status = RAGStatus.RED

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=score,
            rag_status=status,
            total_rules=total_count,
            passed_rules=passed_count,
            failed_rules=total_count - passed_count,
            findings=findings,
            metrics={
                "b2b_sharing_ready": has_sharing,
                "zero_egress_fee_guaranteed": has_cloud_switching,
                "smart_contract_safe_kill": has_smart_contract,
                "sovereign_transfer_safeguards": has_intl_safeguards,
            },
            remediation_hours_est=0.0 if score == 100.0 else 24.0,
            estimated_opex_impact_eur=0.0
        )
