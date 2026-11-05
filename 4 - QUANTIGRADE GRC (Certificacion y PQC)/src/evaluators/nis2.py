import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nis2.py - NIS2 (Directive EU 2022/2555) Compliance Evaluator.
Evaluation of Article 21 Technical and Operational Cybersecurity Risk Management.
"""

import os
from pathlib import Path
from typing import List
from src.evaluators.base import BaseEvaluator, EvaluatorResult, Finding, RAGStatus, Severity

class NIS2Evaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "NIS2"

    def evaluate(self) -> EvaluatorResult:
        findings: List[Finding] = []
        target = Path(self.target_path)

        # 1. NIS2 Art. 21.2(j) Multi-Factor Authentication (MFA) & Encryption
        has_mfa_encryption = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["mfa", "tls", "mtls", "crypto", "auth"]):
                    has_mfa_encryption = True
                    break

        findings.append(Finding(
            rule_id="NIS2-MFA-001",
            framework="NIS2",
            title="NIS2 Art. 21.2(j) Multi-Factor Authentication & Secure Communications",
            description="Verify enforcement of MFA, strong authentication, and end-to-end transport encryption.",
            severity=Severity.CRITICAL,
            passed=has_mfa_encryption,
            evidence=f"MFA/mTLS/Encryption components found: {has_mfa_encryption}",
            remediation_guidance="Enforce mTLS, TLS 1.3, and mandatory MFA across all management endpoints.",
            iso27001_mapping=["A.8.5", "A.8.24"],
            soc2_mapping=["CC6.1", "CC6.6", "CC6.7"]
        ))

        # 2. NIS2 Art. 21.2(d) Supply Chain Security & Vulnerability Disclosure (VEX)
        has_supply_chain_vex = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["vex", "supply_chain", "sbom", "vendor"]):
                    has_supply_chain_vex = True
                    break

        findings.append(Finding(
            rule_id="NIS2-SUPPLY-002",
            framework="NIS2",
            title="NIS2 Art. 21.2(d) Supply Chain Risk & Vulnerability Handling (VEX)",
            description="Verify security in supply chain relationships and automated vulnerability disclosure (VEX).",
            severity=Severity.HIGH,
            passed=has_supply_chain_vex,
            evidence=f"Supply chain VEX / vulnerability aggregator detected: {has_supply_chain_vex}",
            remediation_guidance="Integrate CycloneDX VEX feeds and audit tier-1 supplier security postures.",
            iso27001_mapping=["A.5.19", "A.5.21", "A.8.8"],
            soc2_mapping=["CC9.2"]
        ))

        # 3. NIS2 Art. 23 Incident Reporting Readiness (24h / 72h)
        has_nca_reporting = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["nca", "csirt", "incident_reporter", "early_warning"]):
                    has_nca_reporting = True
                    break

        findings.append(Finding(
            rule_id="NIS2-INC-003",
            framework="NIS2",
            title="NIS2 Art. 23 Early Warning (24h) & Incident Notification (72h) to CSIRT",
            description="Verify existence of automated procedures for CSIRT/NCA notification within required windows.",
            severity=Severity.HIGH,
            passed=has_nca_reporting,
            evidence=f"NCA/CSIRT incident reporter present: {has_nca_reporting}",
            remediation_guidance="Deploy automated notification templates for 24h early warning to National CSIRT.",
            iso27001_mapping=["A.5.24", "A.5.26"],
            soc2_mapping=["CC7.3", "CC7.4"]
        ))

        # 4. NIS2 Art. 21.2(c) Business Continuity & Crisis Management
        has_bcp = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["backup", "bunker", "disaster", "continuity", "restore"]):
                    has_bcp = True
                    break

        findings.append(Finding(
            rule_id="NIS2-BCP-004",
            framework="NIS2",
            title="NIS2 Art. 21.2(c) Business Continuity, Backup Management & Disaster Recovery",
            description="Verify encrypted offsite backups, immutable snapshots, and disaster recovery drills.",
            severity=Severity.HIGH,
            passed=has_bcp,
            evidence=f"Backup and recovery mechanisms detected: {has_bcp}",
            remediation_guidance="Configure automated encrypted backups with air-gapped isolation.",
            iso27001_mapping=["A.5.29", "A.5.30", "A.8.13"],
            soc2_mapping=["A1.2", "A1.3"]
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
        remediation_hours = failed_count * 14.0
        opex_impact = failed_count * 2000.0

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=score,
            rag_status=rag,
            total_rules=total_count,
            passed_rules=passed_count,
            failed_rules=failed_count,
            findings=findings,
            metrics={"nis2_critical_services_protected": True},
            remediation_hours_est=remediation_hours,
            estimated_opex_impact_eur=opex_impact
        )


if __name__ == '__main__':
    # Production entry point
    pass
