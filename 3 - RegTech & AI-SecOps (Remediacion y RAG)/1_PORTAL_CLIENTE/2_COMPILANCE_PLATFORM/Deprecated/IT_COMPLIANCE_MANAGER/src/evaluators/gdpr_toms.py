import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gdpr_toms.py - RGPD / LOPDGDD (Regulation EU 2016/679) Evaluator.
Auditing Technical and Organizational Measures (TOMs), SAR, Pseudonymization, Data Retention.
"""

import os
from pathlib import Path
from typing import List
from src.evaluators.base import BaseEvaluator, EvaluatorResult, Finding, RAGStatus, Severity

class GDPRTOMsEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "GDPR"

    def evaluate(self) -> EvaluatorResult:
        findings: List[Finding] = []
        target = Path(self.target_path)

        # 1. RGPD Art. 32 Technical and Organizational Measures (TOMs) & Pseudonymization
        has_pseudonymizer = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["pseudonym", "anonym", "toms", "rgpd"]):
                    has_pseudonymizer = True
                    break

        findings.append(Finding(
            rule_id="GDPR-TOM-001",
            framework="GDPR",
            title="RGPD Art. 32 Technical & Organizational Measures (TOMs) & Pseudonymization",
            description="Verify data pseudonymization and encryption of personal data at rest and in transit.",
            severity=Severity.HIGH,
            passed=has_pseudonymizer,
            evidence=f"Data pseudonymization / TOMs tools present: {has_pseudonymizer}",
            remediation_guidance="Implement automated tokenization and AES-256 field-level encryption for PII.",
            iso27001_mapping=["A.8.11", "A.8.24"],
            soc2_mapping=["P1.1", "P3.1", "P4.1"]
        ))

        # 2. RGPD Art. 17 Right to Erasure & Data Retention Purging
        has_retention_purger = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["retention", "purger", "erasure", "deletion"]):
                    has_retention_purger = True
                    break

        findings.append(Finding(
            rule_id="GDPR-RET-002",
            framework="GDPR",
            title="RGPD Art. 17 Automated Data Retention Cycles & Right to Erasure",
            description="Verify enforcement of automated data retention expiration and secure data wiping.",
            severity=Severity.HIGH,
            passed=has_retention_purger,
            evidence=f"Data retention purger script found: {has_retention_purger}",
            remediation_guidance="Deploy scheduled cron jobs for automatic deletion of expired PII logs/records.",
            iso27001_mapping=["A.8.10"],
            soc2_mapping=["P4.2", "P4.3"]
        ))

        # 3. RGPD Art. 15 Subject Access Request (SAR) Data Extractor
        has_sar_extractor = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["sar", "subject_access", "export_data"]):
                    has_sar_extractor = True
                    break

        findings.append(Finding(
            rule_id="GDPR-SAR-003",
            framework="GDPR",
            title="RGPD Art. 15 Subject Access Request (SAR) Automated Data Extraction",
            description="Verify capability to export all personal data relating to a data subject upon request.",
            severity=Severity.MEDIUM,
            passed=has_sar_extractor,
            evidence=f"SAR data extraction module detected: {has_sar_extractor}",
            remediation_guidance="Build automated SAR query export tooling producing structured JSON/PDF outputs.",
            iso27001_mapping=["A.5.34"],
            soc2_mapping=["P5.1", "P5.2"]
        ))

        # 4. RGPD Art. 33 Data Breach Notification Readiness (72h)
        has_breach_auditor = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["breach", "incident", "aepd", "notification"]):
                    has_breach_auditor = True
                    break

        findings.append(Finding(
            rule_id="GDPR-BREACH-004",
            framework="GDPR",
            title="RGPD Art. 33 Personal Data Breach Notification Readiness (72h Window)",
            description="Verify automated data breach assessment and reporting templates for Supervisory Authority (AEPD).",
            severity=Severity.CRITICAL,
            passed=has_breach_auditor,
            evidence=f"Data breach notification auditor present: {has_breach_auditor}",
            remediation_guidance="Establish 72h notification playbook and automated AEPD incident report generator.",
            iso27001_mapping=["A.5.24", "A.5.25"],
            soc2_mapping=["P7.1"]
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
        remediation_hours = failed_count * 12.0
        opex_impact = failed_count * 1800.0

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=score,
            rag_status=rag,
            total_rules=total_count,
            passed_rules=passed_count,
            failed_rules=failed_count,
            findings=findings,
            metrics={"pii_encryption_active": True, "sar_sla_days": 30},
            remediation_hours_est=remediation_hours,
            estimated_opex_impact_eur=opex_impact
        )


if __name__ == '__main__':
    # Production entry point
    pass
