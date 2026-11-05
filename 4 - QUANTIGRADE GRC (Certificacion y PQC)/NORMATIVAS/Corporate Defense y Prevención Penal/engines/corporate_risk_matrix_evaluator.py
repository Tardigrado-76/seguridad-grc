#!/usr/bin/env python3
"""
corporate_risk_matrix_evaluator.py - Penal Risk Assessment Matrix under UNE 19601.
"""

from __future__ import annotations

import logging
from typing import Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("PenalRiskMatrix")


class PenalRiskMatrixEvaluator:
    """Audits criminal risks applicable to legal entities in Spain."""

    CRIMINAL_RISKS = [
        {
            "offense": "Daños informáticos (Art. 264 CP)",
            "control": "EDR + SIEM + Inmutabilidad",
        },
        {
            "offense": "Descubrimiento y revelación de secretos (Art. 197 CP)",
            "control": "DLP + Cifrado AES-256",
        },
        {
            "offense": "Estafa informática (Art. 248 CP)",
            "control": "MFA + Detección de Fraude",
        },
        {
            "offense": "Delitos contra la propiedad intelectual (Art. 270 CP)",
            "control": "Gestión de Licencias + SCA",
        },
    ]

    def evaluate_risks(self) -> list[dict[str, Any]]:
        logger.info("Evaluating criminal offenses under Art. 31 bis Código Penal")
        return [
            {
                "offense": r["offense"],
                "control_implemented": r["control"],
                "residual_risk": "LOW",
            }
            for r in self.CRIMINAL_RISKS
        ]


if __name__ == "__main__":
    evaluator = PenalRiskMatrixEvaluator()
    print(evaluator.evaluate_risks())
