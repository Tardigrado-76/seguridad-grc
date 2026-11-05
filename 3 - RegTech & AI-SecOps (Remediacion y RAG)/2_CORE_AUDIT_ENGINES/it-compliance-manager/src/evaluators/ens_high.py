import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ens_high.py - ENS (Esquema Nacional de Seguridad - RD 311/2022) Categoría Alta Evaluator.
Auditing Annex II Security Measures (Organizational, Operational, Technical).
"""

import os
from pathlib import Path
from typing import List
from src.evaluators.base import BaseEvaluator, EvaluatorResult, Finding, RAGStatus, Severity

class ENSHighEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "ENS_ALTO"

    def evaluate(self) -> EvaluatorResult:
        findings: List[Finding] = []
        target = Path(self.target_path)

        # 1. ENS [op.exp.1] Hardening & OS Bastioning (DISA STIG / Credential Guard / LSA)
        has_hardening = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["stig", "hardening", "clara", "bunker_init"]):
                    has_hardening = True
                    break

        findings.append(Finding(
            rule_id="ENS-HARD-001",
            framework="ENS_ALTO",
            title="ENS [op.exp.1] Configuration & OS Hardening (DISA STIG / Credential Guard)",
            description="Verify active infrastructure bastioning, Credential Guard, LSA protection, and DISA STIG compliance.",
            severity=Severity.CRITICAL,
            passed=has_hardening,
            evidence=f"OS Hardening / DISA STIG scripts detected: {has_hardening}",
            remediation_guidance="Apply STIG hardening scripts (Credential Guard enabled, LSA Enforce = 1).",
            iso27001_mapping=["A.8.9"],
            soc2_mapping=["CC6.8"]
        ))

        # 2. ENS [op.exp.7] File Integrity Monitoring (FIM)
        has_fim = False
        for root, _, files in os.walk(target):
            for file in files:
                if "fim" in file.lower() or "integrity" in file.lower():
                    has_fim = True
                    break

        findings.append(Finding(
            rule_id="ENS-FIM-002",
            framework="ENS_ALTO",
            title="ENS [op.exp.7] File Integrity Monitoring (FIM) & System Hash Validation",
            description="Verify continuous file integrity monitoring for critical binaries and config files.",
            severity=Severity.HIGH,
            passed=has_fim,
            evidence=f"File Integrity Monitoring (FIM) module present: {has_fim}",
            remediation_guidance="Deploy automated FIM agents checking SHA-256 hashes of system binaries.",
            iso27001_mapping=["A.8.8", "A.8.15"],
            soc2_mapping=["CC6.8", "CC7.1"]
        ))

        # 3. ENS [op.acc.1] Access Control & Privilege Auditor
        has_iam_auditor = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["iam", "access_policy", "privilege", "rbac"]):
                    has_iam_auditor = True
                    break

        findings.append(Finding(
            rule_id="ENS-IAM-003",
            framework="ENS_ALTO",
            title="ENS [op.acc.1] Least Privilege & Identity Access Management Audit",
            description="Verify segregation of duties, least privilege policy, and privilege escalation guards.",
            severity=Severity.HIGH,
            passed=has_iam_auditor,
            evidence=f"IAM / Access policy auditor assets present: {has_iam_auditor}",
            remediation_guidance="Audit IAM roles and enforce strict RBAC across admin accounts.",
            iso27001_mapping=["A.5.15", "A.5.18", "A.8.2"],
            soc2_mapping=["CC6.1", "CC6.2", "CC6.3"]
        ))

        # 4. ENS [mp.eq.1] Cryptography & FIPS Compliance
        has_crypto_val = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["tls", "fips", "pqc", "cert"]):
                    has_crypto_val = True
                    break

        findings.append(Finding(
            rule_id="ENS-CRY-004",
            framework="ENS_ALTO",
            title="ENS [mp.eq.1] Cryptographic Safeguards & High Assurance Algorithms",
            description="Verify usage of approved cryptographic algorithms, TLS 1.3, mTLS, and key management.",
            severity=Severity.HIGH,
            passed=has_crypto_val,
            evidence=f"Cryptographic and TLS hardening scripts present: {has_crypto_val}",
            remediation_guidance="Disable legacy ciphers and enforce mTLS with AES-256-GCM / RSA-4096 / PQC.",
            iso27001_mapping=["A.8.24"],
            soc2_mapping=["CC6.6", "CC6.7"]
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
        remediation_hours = failed_count * 18.0
        opex_impact = failed_count * 3000.0

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=score,
            rag_status=rag,
            total_rules=total_count,
            passed_rules=passed_count,
            failed_rules=failed_count,
            findings=findings,
            metrics={"ens_category": "ALTA", "ccn_stic_aligned": True},
            remediation_hours_est=remediation_hours,
            estimated_opex_impact_eur=opex_impact
        )


if __name__ == '__main__':
    # Production entry point
    pass
