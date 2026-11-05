from __future__ import annotations
from typing import Dict, Any

class FinancialImpactQuantifier:
    """Models financial risk exposure, regulatory fines, and remediation ROI across frameworks."""

    STATUTORY_FINES = {
        "EU_AI_ACT": {"max_fixed": 35_000_000.0, "pct_turnover": 0.07},
        "RGPD": {"max_fixed": 20_000_000.0, "pct_turnover": 0.04},
        "NIS2": {"max_fixed": 10_000_000.0, "pct_turnover": 0.02},
        "DORA": {"max_fixed": 5_000_000.0, "pct_turnover": 0.01},
        "DSA": {"max_fixed": 25_000_000.0, "pct_turnover": 0.06},
        "LGTEL": {"max_fixed": 20_000_000.0, "pct_turnover": 0.02},
        "LPIC": {"max_fixed": 15_000_000.0, "pct_turnover": 0.03},
        "DGAM": {"max_fixed": 20_000_000.0, "pct_turnover": 0.03},
        "ITAR_EAR": {"max_fixed": 25_000_000.0, "pct_turnover": 0.05},
        "MCCE": {"max_fixed": 30_000_000.0, "pct_turnover": 0.04},
        "ISA_IEC_62443": {"max_fixed": 15_000_000.0, "pct_turnover": 0.02},
        "DPP_CUSTOMS": {"max_fixed": 10_000_000.0, "pct_turnover": 0.02},
        "DEFAULT": {"max_fixed": 2_000_000.0, "pct_turnover": 0.01}
    }

    @classmethod
    def calculate_exposure(
        cls,
        framework_key: str,
        annual_turnover_eur: float,
        compliance_score: float,
        remediation_hours: float = 0.0
    ) -> Dict[str, Any]:
        statute = cls.STATUTORY_FINES.get(framework_key.upper(), cls.STATUTORY_FINES["DEFAULT"])
        fine_by_turnover = annual_turnover_eur * statute["pct_turnover"]
        max_statutory_fine = max(statute["max_fixed"], fine_by_turnover)

        # Non-compliance risk factor (0.0 to 1.0)
        risk_factor = max(0.0, (100.0 - compliance_score) / 100.0)
        residual_risk_eur = round(max_statutory_fine * risk_factor, 2)

        remediation_cost_eur = round(remediation_hours * 85.0, 2)
        roci_ratio = f"{round(max_statutory_fine / max(1.0, remediation_cost_eur), 1)}x" if remediation_cost_eur > 0 else "N/A"

        return {
            "framework": framework_key,
            "annual_turnover_eur": annual_turnover_eur,
            "max_potential_fine_eur": max_statutory_fine,
            "max_potential_fine_formatted": f"{max_statutory_fine:,.2f} €",
            "residual_risk_eur": residual_risk_eur,
            "residual_risk_eur_formatted": f"{residual_risk_eur:,.2f} €",
            "remediation_budget_eur": remediation_cost_eur,
            "remediation_budget_eur_formatted": f"{remediation_cost_eur:,.2f} €",
            "roci_ratio": roci_ratio
        }
