#!/usr/bin/env python3
"""
framework_business_executive.py - Business Execution Layer for MCCE_CIBERDEFENSA_MILITAR_OTAN.
Generates SLSA L3+ Merkle Bunker seals, military CISO dictamens, and statutory national defense exposure.
"""

from __future__ import annotations

import sys
from pathlib import Path

GCR_ROOT = Path(r"E:/PROYECTOS IA/GCR")
if str(GCR_ROOT) not in sys.path:
    sys.path.insert(0, str(GCR_ROOT))

from core_mesh.business_execution import (
    ExecutiveDictamenGenerator,
    FinancialImpactQuantifier,
    MerkleBunker,
)


class FrameworkBusinessExecutive:
    def __init__(self, company_name: str = "Iberia Sovereign Defense Cloud S.A.", turnover_eur: float = 200_000_000.0):
        self.company_name = company_name
        self.turnover_eur = turnover_eur
        self.framework_id = "MCCE_CIBERDEFENSA_MILITAR_OTAN"
        self.framework_name = "MCCE Ciberdefensa Militar & Información Clasificada OTAN (STANAG 4774 & CCN-STIC 400)"
        self.bunker = MerkleBunker()

    def execute_business_governance(self, compliance_score: float = 100.0, rag_status: str = "GREEN", total_rules: int = 4, passed_rules: int = 4) -> dict:
        """Seals military cyberdefense evidence, computes statutory exposure, and issues formal CISO Executive Dictamen."""
        evidence = {'mcce_csirt_linked': True, 'stanag_4774_labeled': True, 'ccn_stic_400_accredited': True}
        seal = self.bunker.seal_audit_evidence(self.company_name, [self.framework_id], evidence)
        financial = FinancialImpactQuantifier.calculate_exposure("MCCE", self.turnover_eur, compliance_score)

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
    print("MCCE Seal ID:", res["seal"].seal_id)
    print("Max National Security Risk Exposure:", res["financial_exposure"]["max_potential_fine_formatted"])
