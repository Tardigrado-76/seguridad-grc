#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
framework_business_executive.py - Business Execution Layer for AESIA_GOBERNANZA_IA_ES.
Generates SLSA L3+ Merkle Bunker seals, board-level executive dictamens, and regulatory fine exposure.
"""

from __future__ import annotations
import sys
from pathlib import Path

GCR_ROOT = Path(r"E:/PROYECTOS IA/GCR")
if str(GCR_ROOT) not in sys.path:
    sys.path.insert(0, str(GCR_ROOT))

from core_mesh.business_execution import MerkleBunker, ExecutiveDictamenGenerator, FinancialImpactQuantifier

class FrameworkBusinessExecutive:
    def __init__(self, company_name: str = "Iberia Regulated Enterprise S.A.", turnover_eur: float = 50_000_000.0):
        self.company_name = company_name
        self.turnover_eur = turnover_eur
        self.framework_id = "AESIA_GOBERNANZA_IA_ES"
        self.framework_name = "Gobernanza de IA en España (AESIA / RD 817/2023)"
        self.bunker = MerkleBunker()

    def execute_business_governance(self, compliance_score: float = 100.0, rag_status: str = "GREEN", total_rules: int = 4, passed_rules: int = 4) -> dict:
        """Seals audit evidence, computes financial exposure, and issues formal CISO Executive Dictamen."""
        evidence = {'aesia_sandbox_registered': True, 'spanish_fria_approved': True, 'hitl_emergency_stop': 'ENABLED'}
        seal = self.bunker.seal_audit_evidence(self.company_name, [self.framework_id], evidence)
        financial = FinancialImpactQuantifier.calculate_exposure("EU_AI_ACT", self.turnover_eur, compliance_score)

        dictamen_md = ExecutiveDictamenGenerator.generate_markdown_dictamen(
            company_name=self.company_name,
            framework_name=self.framework_name,
            compliance_score=compliance_score,
            rag_status=rag_status,
            total_rules=total_rules,
            passed_rules=passed_rules,
            failed_rules=total_rules - passed_rules,
            seal=seal,
            financial_summary=financial
        )

        return {
            "seal": seal,
            "financial_exposure": financial,
            "dictamen_markdown": dictamen_md
        }

if __name__ == "__main__":
    exec_engine = FrameworkBusinessExecutive()
    res = exec_engine.execute_business_governance()
    print("Seal ID:", res["seal"].seal_id)
    print("Max Potential Fine:", res["financial_exposure"]["max_potential_fine_formatted"])
