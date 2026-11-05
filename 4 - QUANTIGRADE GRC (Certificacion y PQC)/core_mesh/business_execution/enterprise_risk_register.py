"""Quantigrade GCR - Enterprise Risk Register & FAIR Quantitative Financial Modeling.

Provides 5x5 Inherent vs. Residual heatmaps, Factor Analysis of Information Risk (FAIR)
financial quantification (ALE = ARO x SLE), and risk treatment workflow governance with SLAs.
Executes 100% natively in Python without Docker or external runtime dependencies.
"""

import time
from typing import Dict, Any, List, Optional

class EnterpriseRiskRegister:
    """Enterprise Risk Register with 5x5 scoring, FAIR quantitative metrics, and treatment SLAs."""

    SEVERITY_LEVELS = {
        "CRITICAL": (20, 25),
        "HIGH": (12, 19),
        "MEDIUM": (6, 11),
        "LOW": (1, 5)
    }

    VALID_STRATEGIES = {"Mitigate", "Transfer", "Accept", "Avoid"}

    def __init__(self, company_annual_turnover: float = 10_000_000.0):
        self.turnover = max(1.0, float(company_annual_turnover))
        self.risks: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def score_to_severity(cls, score: float) -> str:
        """Maps numerical score (1-25) to standard risk severity level."""
        if score >= 20.0:
            return "CRITICAL"
        elif score >= 12.0:
            return "HIGH"
        elif score >= 6.0:
            return "MEDIUM"
        else:
            return "LOW"

    def add_risk(
        self,
        risk_id: str,
        title: str,
        category: str,
        likelihood: int,
        impact: int,
        existing_controls: Optional[List[str]] = None,
        control_efficacy: float = 0.0,
        financial_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Registers a risk with inherent score, residual calculation, and FAIR financial metrics."""
        lh = max(1, min(5, int(likelihood)))
        imp = max(1, min(5, int(impact)))
        inh_score = lh * imp
        inh_severity = self.score_to_severity(inh_score)

        eff = max(0.0, min(1.0, float(control_efficacy)))
        res_score = round(inh_score * (1.0 - eff), 2)
        res_severity = self.score_to_severity(res_score)

        # FAIR Model parameters
        fin = financial_params or {}
        aro = max(0.0, float(fin.get("aro", 0.1)))  # Annualized Rate of Occurrence
        sle = max(0.0, float(fin.get("sle", 50_000.0)))  # Single Loss Expectancy in EUR
        ale = round(aro * sle * (1.0 - (eff * 0.7)), 2)  # Control efficacy mitigates financial ALE
        mpl_pct = round((sle / self.turnover) * 100.0, 3)

        risk_entry = {
            "risk_id": risk_id,
            "title": title,
            "category": category,
            "likelihood": lh,
            "impact": imp,
            "inherent_score": inh_score,
            "inherent_severity": inh_severity,
            "existing_controls": existing_controls or [],
            "control_efficacy": eff,
            "residual_score": res_score,
            "residual_severity": res_severity,
            "fair_metrics": {
                "aro": aro,
                "sle": sle,
                "ale": ale,
                "maximum_probable_loss_percentage": mpl_pct
            },
            "treatment_plan": None,
            "created_at": time.time()
        }
        self.risks[risk_id] = risk_entry
        return risk_entry

    def set_treatment_plan(
        self,
        risk_id: str,
        strategy: str,
        owner: str,
        target_residual_score: float,
        sla_days: int
    ) -> Dict[str, Any]:
        """Configures a risk treatment decision and monitors SLA compliance."""
        if risk_id not in self.risks:
            raise KeyError(f"Risk '{risk_id}' not found in Enterprise Risk Register.")

        norm_strat = strategy.strip().capitalize()
        if norm_strat not in self.VALID_STRATEGIES:
            raise ValueError(f"Invalid strategy '{strategy}'. Must be one of {self.VALID_STRATEGIES}.")

        now = time.time()
        deadline = now + (sla_days * 86400)
        treatment = {
            "strategy": norm_strat,
            "owner": owner,
            "target_residual_score": float(target_residual_score),
            "sla_days": sla_days,
            "deadline_utc": deadline,
            "assigned_at": now,
            "status": "IN_PROGRESS"
        }
        self.risks[risk_id]["treatment_plan"] = treatment
        return treatment

    def get_risk_status(self, risk_id: str, current_time: Optional[float] = None) -> Dict[str, Any]:
        """Returns risk status along with remaining SLA days for treatment."""
        if risk_id not in self.risks:
            raise KeyError(f"Risk '{risk_id}' not found.")
        
        risk = self.risks[risk_id]
        now = current_time if current_time is not None else time.time()
        treatment = risk.get("treatment_plan")
        sla_status = "NO_PLAN"
        days_remaining = None

        if treatment:
            deadline = treatment.get("deadline_utc", now)
            diff_sec = deadline - now
            days_remaining = round(diff_sec / 86400.0, 1)
            if days_remaining < 0:
                sla_status = "OVERDUE"
            elif days_remaining <= 7.0:
                sla_status = "WARNING"
            else:
                sla_status = "ON_TRACK"

        return {
            "risk_id": risk_id,
            "title": risk["title"],
            "inherent_severity": risk["inherent_severity"],
            "residual_severity": risk["residual_severity"],
            "ale": risk["fair_metrics"]["ale"],
            "treatment_strategy": treatment["strategy"] if treatment else None,
            "sla_status": sla_status,
            "days_remaining": days_remaining
        }

    def get_risk_matrix_summary(self) -> Dict[str, Any]:
        """Produces aggregated corporate summary, 5x5 distribution, and total ALE."""
        total_risks = len(self.risks)
        inherent_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        residual_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_ale = 0.0
        total_inh_score = 0.0
        total_res_score = 0.0

        for r in self.risks.values():
            inherent_counts[r["inherent_severity"]] += 1
            residual_counts[r["residual_severity"]] += 1
            total_ale += r["fair_metrics"]["ale"]
            total_inh_score += r["inherent_score"]
            total_res_score += r["residual_score"]

        mitigation_rate = 0.0
        if total_inh_score > 0:
            mitigation_rate = round((1.0 - (total_res_score / total_inh_score)) * 100.0, 1)

        return {
            "total_risks": total_risks,
            "inherent_distribution": inherent_counts,
            "residual_distribution": residual_counts,
            "total_annualized_loss_expectancy_eur": round(total_ale, 2),
            "aggregate_mitigation_rate_percentage": mitigation_rate,
            "turnover_exposure_percentage": round((total_ale / self.turnover) * 100.0, 3)
        }
