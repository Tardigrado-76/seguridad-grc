#!/usr/bin/env python3
"""
lpic_pso_ppe_cnpic_compliance_engine.py - Critical Infrastructure Protection Engine.
Implements Ley 8/2011 (LPIC), Real Decreto 704/2011 (Reglamento PIC),
Plan de Seguridad del Operador (PSO), and Plan de Protección Específico (PPE) under CNPIC.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("LPICEngine")


class LpicComplianceEngine:
    """Manages Operator Security Plans (PSO) and Specific Protection Plans (PPE) for CNPIC."""

    def __init__(self, critical_operator_name: str, sector: str):
        self.critical_operator_name = critical_operator_name
        self.sector = sector

    def validate_pso_structure(
        self, rso_designated: bool, risk_methodology_approved: bool
    ) -> dict[str, Any]:
        """Validates formal Plan de Seguridad del Operador (PSO) pursuant to Ley 8/2011 Art. 13."""
        if not (rso_designated and risk_methodology_approved):
            raise ValueError(
                "PSO mandates designation of Responsable de Seguridad y Enlace (RSO) and formal risk methodology."
            )

        logger.info(
            f"PSO validated for critical operator {self.critical_operator_name}"
        )
        return {
            "operator": self.critical_operator_name,
            "sector": self.sector,
            "pso_status": "APPROVED_CNPIC",
            "rso_registered": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def validate_ppe_airgap_controls(
        self, airgap_enforced: bool, immutable_backups: bool
    ) -> bool:
        """Validates cyber-physical protection measures under Real Decreto 704/2011 Art. 24."""
        if not (airgap_enforced and immutable_backups):
            raise ValueError(
                "PPE requires air-gap separation and immutable off-site backups for vital assets."
            )
        logger.info("PPE cyber-physical isolation controls validated")
        return True


if __name__ == "__main__":
    engine = LpicComplianceEngine("Red Eléctrica e Hídrica Nacional", "ENERGÍA Y AGUA")
    pso = engine.validate_pso_structure(True, True)
    ppe_valid = engine.validate_ppe_airgap_controls(True, True)
    print(json.dumps({"pso": pso, "ppe_valid": ppe_valid}, indent=2))
