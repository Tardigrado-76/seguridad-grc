#!/usr/bin/env python3
"""
dsa.py - Digital Services Act (Regulation EU 2022/2065) Compliance Evaluator.
Auditing Notice & Action Mechanisms (Art. 16), Statement of Reasons & Internal Complaints (Arts. 17, 20),
Transparency Reporting & Recommender Systems (Arts. 15, 24, 27), and Anti-Dark Patterns & Protection of Minors (Arts. 25, 28).
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


class DSAEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "DSA"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)

        # 1. Art. 16: Notice and Action Mechanism
        has_notice_action = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["notice", "moderation", "illegal_content"]):
                    has_notice_action = True
                    break

        findings.append(Finding(
            rule_id="DSA-NOTICE-001",
            framework="DSA",
            title="DSA Art. 16 Notice and Action Mechanisms for Illegal Content",
            description="Verify electronic notice and action mechanisms allowing timely, diligent, and objective notification of alleged illegal content.",
            severity=Severity.CRITICAL,
            passed=has_notice_action,
            evidence=f"Notice and Action moderation engine present: {has_notice_action}",
            remediation_guidance="Deploy standardized electronic forms and API endpoints for receiving notices under Art. 16.",
            iso27001_mapping=["A.5.10", "A.5.24"],
            soc2_mapping=["CC6.1", "CC7.3"]
        ))

        # 2. Arts. 17 & 20: Statement of Reasons & Complaint-Handling
        has_reasons_complaints = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["statement", "reasons", "moderation", "complaint", "appeal"]):
                    has_reasons_complaints = True
                    break

        findings.append(Finding(
            rule_id="DSA-REASONS-002",
            framework="DSA",
            title="DSA Arts. 17 & 20 Statement of Reasons & Internal Complaint-Handling System",
            description="Verify automated generation of clear and specific statements of reasons transmissible to the DSA Transparency Database, and human-in-the-loop appeal processing.",
            severity=Severity.HIGH,
            passed=has_reasons_complaints,
            evidence=f"Statement of Reasons and complaint handling present: {has_reasons_complaints}",
            remediation_guidance="Standardize reasons for content restrictions and provide at least 6 months for internal appeals.",
            iso27001_mapping=["A.5.28", "A.5.29"],
            soc2_mapping=["CC2.2", "CC7.4"]
        ))

        # 3. Arts. 15, 24 & 27: Transparency Reports & Recommender Systems
        has_transparency = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["transparency", "recommender", "ranking"]):
                    has_transparency = True
                    break

        findings.append(Finding(
            rule_id="DSA-TRANSP-003",
            framework="DSA",
            title="DSA Arts. 15, 24 & 27 Periodic Transparency Reports & Algorithmic Recommender Transparency",
            description="Verify periodic public reporting on content moderation orders and notices, plus plain-language disclosure and non-profiling options for recommender systems.",
            severity=Severity.HIGH,
            passed=has_transparency,
            evidence=f"Transparency reporting generator and recommender audit present: {has_transparency}",
            remediation_guidance="Publish semi-annual transparency reports and offer users a chronological or non-profiling feed alternative.",
            iso27001_mapping=["A.5.8", "A.8.28"],
            soc2_mapping=["CC6.6", "CC6.8"]
        ))

        # 4. Arts. 25 & 28: Anti-Dark Patterns & Protection of Minors
        has_safety_minors = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["dark_pattern", "minors", "safety", "guard"]):
                    has_safety_minors = True
                    break

        findings.append(Finding(
            rule_id="DSA-SAFETY-004",
            framework="DSA",
            title="DSA Arts. 25 & 28 Prohibition of Dark Patterns & Online Minor Safety Safeguards",
            description="Verify prohibition of deceptive choice architecture (dark patterns) in user interfaces and strict ban on profiling-based advertising directed at minors.",
            severity=Severity.CRITICAL,
            passed=has_safety_minors,
            evidence=f"Anti-dark patterns and minors protection guard present: {has_safety_minors}",
            remediation_guidance="Eliminate confirmshaming and pre-ticked boxes, and disable behavioral ad targeting for minor accounts.",
            iso27001_mapping=["A.8.25", "A.8.28"],
            soc2_mapping=["CC6.1", "CC7.1"]
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
                "notice_and_action_active": has_notice_action,
                "statement_of_reasons_automated": has_reasons_complaints,
                "transparency_reporting_conformant": has_transparency,
                "clean_ui_and_minors_shielded": has_safety_minors,
            },
            remediation_hours_est=0.0 if score == 100.0 else 24.0,
            estimated_opex_impact_eur=0.0
        )
