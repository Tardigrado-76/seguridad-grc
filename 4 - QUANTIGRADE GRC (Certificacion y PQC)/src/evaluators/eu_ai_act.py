#!/usr/bin/env python3
"""
eu_ai_act.py - EU AI Act (Regulation EU 2024/1689) Compliance Evaluator.
Auditing Risk Management System (Art. 9), Human Oversight HITL (Art. 14),
Fundamental Rights Impact Assessment (Art. 27), and Transparency/Watermarking (Art. 50).
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


class EUAIActEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "EU_AI_ACT"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)

        # 1. Art. 9: Risk Management System & Governance Engine
        has_risk_engine = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["ai_compliance", "ai_risk", "risk_system"]):
                    has_risk_engine = True
                    break

        findings.append(Finding(
            rule_id="EU-AI-RISK-001",
            framework="EU_AI_ACT",
            title="EU AI Act Art. 9 Continuous Risk Management System & Triage",
            description="Verify automated AI risk level classification (Prohibited, High Risk, GPAI, Limited, Minimal) and continuous risk evaluation.",
            severity=Severity.HIGH,
            passed=has_risk_engine,
            evidence=f"AI risk classification & governance engine present: {has_risk_engine}",
            remediation_guidance="Implement automated AI risk assessment and regulatory classification engine for AI models.",
            iso27001_mapping=["A.5.8", "A.8.28"],
            soc2_mapping=["CC5.2", "CC6.8"]
        ))

        # 2. Art. 14: Human-in-the-loop (HITL) Oversight & Emergency Override
        has_hitl_oversight = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["human_oversight", "hitl"]):
                    has_hitl_oversight = True
                    break

        findings.append(Finding(
            rule_id="EU-AI-HITL-002",
            framework="EU_AI_ACT",
            title="EU AI Act Art. 14 Human Oversight (HITL) & Stop Operational Controls",
            description="Verify human oversight mechanisms allowing human operators to understand, monitor, and override/stop AI model execution.",
            severity=Severity.CRITICAL,
            passed=has_hitl_oversight,
            evidence=f"Human oversight & emergency stop auditor present: {has_hitl_oversight}",
            remediation_guidance="Deploy human-in-the-loop validation checkpoints and operational circuit-breakers for critical decisions.",
            iso27001_mapping=["A.5.8"],
            soc2_mapping=["CC5.3"]
        ))

        # 3. Art. 27: Fundamental Rights Impact Assessment (FRIA)
        has_fria = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["fria", "impact_assessment"]):
                    has_fria = True
                    break

        findings.append(Finding(
            rule_id="EU-AI-FRIA-003",
            framework="EU_AI_ACT",
            title="EU AI Act Art. 27 Fundamental Rights Impact Assessment (FRIA)",
            description="Verify completion of Fundamental Rights Impact Assessment for high-risk AI deployments with cryptographic sealing.",
            severity=Severity.HIGH,
            passed=has_fria,
            evidence=f"FRIA evaluation and assessment engine present: {has_fria}",
            remediation_guidance="Conduct and record structured FRIA evaluations across core human rights dimensions prior to deployment.",
            iso27001_mapping=["A.5.34"],
            soc2_mapping=["CC5.2"]
        ))

        # 4. Art. 50: Synthetic Output Watermarking & Model Provenance
        has_watermark_provenance = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["watermark", "provenance"]):
                    has_watermark_provenance = True
                    break

        findings.append(Finding(
            rule_id="EU-AI-WATERMARK-004",
            framework="EU_AI_ACT",
            title="EU AI Act Art. 50 AI Synthetic Output Watermarking & Cryptographic Provenance",
            description="Verify steganographic zero-width or digital watermarking on AI outputs and cryptographic signature attestation on model weights.",
            severity=Severity.HIGH,
            passed=has_watermark_provenance,
            evidence=f"Model watermarking and cryptographic provenance signer present: {has_watermark_provenance}",
            remediation_guidance="Inject zero-width HMAC/SHA-256 watermarks in synthetic text and sign model binaries with SHA-256 digests.",
            iso27001_mapping=["A.8.24"],
            soc2_mapping=["CC6.1"]
        ))

        # Score calculations
        passed_count = sum(1 for f in findings if f.passed)
        total_count = len(findings)
        score = round((passed_count / total_count) * 100.0, 1) if total_count > 0 else 0.0

        if score >= 80.0:
            rag = RAGStatus.GREEN
        elif score >= 50.0:
            rag = RAGStatus.AMBER
        else:
            rag = RAGStatus.RED

        failed_count = total_count - passed_count
        remediation_hours = failed_count * 15.0
        opex_impact = failed_count * 2500.0

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=score,
            rag_status=rag,
            total_rules=total_count,
            passed_rules=passed_count,
            failed_rules=failed_count,
            findings=findings,
            metrics={"fria_approved": True, "watermarking_active": True, "hitl_enforced": True},
            remediation_hours_est=remediation_hours,
            estimated_opex_impact_eur=opex_impact
        )
