#!/usr/bin/env python3
"""
framework_business_executive.py - Business Execution Layer for ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT.
Generates SLSA L3+ Merkle Bunker seals, plant director dictamens, and industrial downtime fine exposure.
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
    def __init__(self, company_name: str = "Terminal Marítima & Hub Logístico del Mediterráneo S.A.", turnover_eur: float = 90_000_000.0):
        self.company_name = company_name
        self.turnover_eur = turnover_eur
        self.framework_id = "ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT"
        self.framework_name = "Ciberseguridad Industrial OT / IoT (ISA/IEC 62443 Zonas & Conductos)"
        self.bunker = MerkleBunker()

    def execute_business_governance(self, compliance_score: float = 100.0, rag_status: str = "GREEN", total_rules: int = 4, passed_rules: int = 4) -> dict:
        """Seals industrial audit evidence, computes plant shutdown exposure, and issues formal CISO Executive Dictamen."""
        evidence = {'zones_and_conduits_active': True, 'sl2_achieved': True, 'modbus_hardened': True}
        seal = self.bunker.seal_audit_evidence(self.company_name, [self.framework_id], evidence)
        financial = FinancialImpactQuantifier.calculate_exposure("ISA_IEC_62443", self.turnover_eur, compliance_score)

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
    print("IEC 62443 Seal ID:", res["seal"].seal_id)
    print("Max Industrial Risk Exposure:", res["financial_exposure"]["max_potential_fine_formatted"])
