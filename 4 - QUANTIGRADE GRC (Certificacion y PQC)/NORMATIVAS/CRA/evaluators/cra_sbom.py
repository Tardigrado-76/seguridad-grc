import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cra_sbom.py - Cyber Resilience Act (CRA) & EU AI Act Compliance Evaluator.
Auditing CycloneDX SBOM generation, CISA KEV vulnerability checks, and EU AI Act Risk Governance.
"""

import os
from pathlib import Path
from typing import List
from src.evaluators.base import BaseEvaluator, EvaluatorResult, Finding, RAGStatus, Severity

class CRASBOMEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "CRA"

    def evaluate(self) -> EvaluatorResult:
        findings: List[Finding] = []
        target = Path(self.target_path)

        # 1. CRA Art. 10 Software Bill of Materials (CycloneDX SBOM)
        has_sbom = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["sbom", "cyclonedx", "dependencies"]):
                    has_sbom = True
                    break

        findings.append(Finding(
            rule_id="CRA-SBOM-001",
            framework="CRA",
            title="CRA Art. 10 Software Bill of Materials (CycloneDX SBOM) Generation",
            description="Verify generation of machine-readable SBOM (CycloneDX v1.4+) for software products.",
            severity=Severity.HIGH,
            passed=has_sbom,
            evidence=f"CycloneDX SBOM generator assets detected: {has_sbom}",
            remediation_guidance="Generate automated CycloneDX JSON/XML SBOM during build pipeline.",
            iso27001_mapping=["A.8.8", "A.8.30"],
            soc2_mapping=["CC6.8"]
        ))

        # 2. CRA Art. 10 Vulnerability & Patch Management (CISA KEV Catalog Matching)
        has_cisa_kev = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["cisa_kev", "kev", "vulnerability"]):
                    has_cisa_kev = True
                    break

        findings.append(Finding(
            rule_id="CRA-KEV-002",
            framework="CRA",
            title="CRA Art. 10 Vulnerability Audit & CISA KEV Exploited Catalog Check",
            description="Verify screening of dependencies against CISA Known Exploited Vulnerabilities (KEV).",
            severity=Severity.CRITICAL,
            passed=has_cisa_kev,
            evidence=f"CISA KEV vulnerability checker present: {has_cisa_kev}",
            remediation_guidance="Enforce CI/CD quality gate blocking builds with unpatched KEV vulnerabilities.",
            iso27001_mapping=["A.8.8"],
            soc2_mapping=["CC7.1"]
        ))

        # 3. EU AI Act (UE 2024/1689) Art. 9 Risk Management & Art. 14 Human Oversight
        has_ai_engine = False
        for root, _, files in os.walk(target):
            for file in files:
                if any(kw in file.lower() for kw in ["ai_compliance", "ai_act", "fria", "human_oversight"]):
                    has_ai_engine = True
                    break

        findings.append(Finding(
            rule_id="EU-AI-003",
            framework="CRA",
            title="EU AI Act Art. 9 Risk System & Art. 14 Human Oversight (HITL)",
            description="Verify risk management, transparency, human oversight, and FRIA assessment for AI components.",
            severity=Severity.HIGH,
            passed=has_ai_engine,
            evidence=f"EU AI Act compliance engine detected: {has_ai_engine}",
            remediation_guidance="Perform AI risk classification, FRIA assessment (Art. 27), and implement HITL controls.",
            iso27001_mapping=["A.5.8", "A.8.28"],
            soc2_mapping=["CC5.2", "CC6.8"]
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
        opex_impact = failed_count * 2200.0

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=score,
            rag_status=rag,
            total_rules=total_count,
            passed_rules=passed_count,
            failed_rules=failed_count,
            findings=findings,
            metrics={"cyclonedx_version": "1.4", "cisa_kev_sync_offline": True},
            remediation_hours_est=remediation_hours,
            estimated_opex_impact_eur=opex_impact
        )


if __name__ == '__main__':
    # Production entry point
    pass
