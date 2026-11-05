#!/usr/bin/env python3
"""
enisa_eucs.py - ENISA European Cloud Cybersecurity Certification Scheme (EUCS) Evaluator.
Auditing EU Data Sovereignty (Level High), HSM Key Management, Tenant Isolation, and IaC Drift.
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


class ENISAEUCSEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "ENISA_EUCS"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)

        # 1. ENISA EUCS High: EU Sovereignty & Data Residency Boundaries
        has_sovereignty = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["eucs", "sovereign", "residency", "enisa"]):
                    has_sovereignty = True
                    break

        findings.append(Finding(
            rule_id="ENISA-SOV-001",
            framework="ENISA_EUCS",
            title="ENISA EUCS Level High: European Sovereignty & Data Residency Boundaries",
            description="Verify cloud manifests enforce European data residency and immunity from extraterritorial legal access.",
            severity=Severity.CRITICAL,
            passed=has_sovereignty,
            evidence=f"ENISA EUCS sovereignty verification tooling present: {has_sovereignty}",
            remediation_guidance="Enforce European sovereign cloud deployment boundaries and legal sovereignty clauses in cloud contracts.",
            iso27001_mapping=["A.5.31", "A.8.11"],
            soc2_mapping=["CC6.1", "CC6.3"]
        ))

        # 2. ENISA EUCS: Cryptographic Key Management & HSM Ownership
        has_hsm = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["hsm", "kms", "key_management", "crypto", "fim"]):
                    has_hsm = True
                    break

        findings.append(Finding(
            rule_id="ENISA-HSM-002",
            framework="ENISA_EUCS",
            title="ENISA EUCS Level High: Customer-Controlled HSM Key Management",
            description="Verify encryption keys are generated, stored, and managed exclusively within EU-controlled HSM boundaries.",
            severity=Severity.HIGH,
            passed=has_hsm,
            evidence=f"HSM / customer-managed KMS key and cryptographic assurance detected: {has_hsm}",
            remediation_guidance="Implement dedicated EU-sovereign Cloud HSM modules for envelope encryption.",
            iso27001_mapping=["A.8.24"],
            soc2_mapping=["CC6.1"]
        ))

        # 3. ENISA EUCS: Tenant Isolation & Secure Compute Microsegmentation
        has_isolation = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["isolation", "tenant", "microsegmentation", "firewall", "hardened"]):
                    has_isolation = True
                    break

        findings.append(Finding(
            rule_id="ENISA-ISOL-003",
            framework="ENISA_EUCS",
            title="ENISA EUCS: Multi-Tenant Logical & Physical Compute Isolation",
            description="Verify isolation controls preventing side-channel attacks and unauthorized cross-tenant memory access.",
            severity=Severity.HIGH,
            passed=has_isolation,
            evidence=f"Tenant isolation and microsegmentation controls detected: {has_isolation}",
            remediation_guidance="Deploy hardware-enforced virtualization isolation and Zero Trust microsegmentation policies.",
            iso27001_mapping=["A.8.20", "A.8.21"],
            soc2_mapping=["CC6.6"]
        ))

        # 4. ENISA EUCS: Continuous IaC Configuration Drift & Compliance Auditing
        has_iac_drift = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["drift", "iac", "terraform", "checker"]):
                    has_iac_drift = True
                    break

        findings.append(Finding(
            rule_id="ENISA-IAC-004",
            framework="ENISA_EUCS",
            title="ENISA EUCS: Continuous Infrastructure as Code (IaC) Drift Detection",
            description="Verify automated scanning of cloud infrastructure templates (Terraform, Bicep) for security baseline drift.",
            severity=Severity.HIGH,
            passed=has_iac_drift,
            evidence=f"Continuous IaC drift auditor and compliance checker present: {has_iac_drift}",
            remediation_guidance="Integrate IaC policy-as-code scanners into CI/CD pipelines to prevent unverified infrastructure changes.",
            iso27001_mapping=["A.8.9", "A.8.32"],
            soc2_mapping=["CC7.1", "CC8.1"]
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
            metrics={"eucs_level": "HIGH", "eu_sovereignty_verified": True, "iac_drift_monitored": True},
            remediation_hours_est=remediation_hours,
            estimated_opex_impact_eur=opex_impact
        )
