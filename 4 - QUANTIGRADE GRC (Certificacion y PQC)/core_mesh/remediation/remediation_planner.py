from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class RemediationAction:
    action_id: str
    rule_id: str
    framework: str
    title: str
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW
    estimated_hours: float
    estimated_cost_eur: float
    assigned_role: str
    automation_eligible: bool
    requires_hitl: bool
    remediation_steps: List[str] = field(default_factory=list)

class RemediationPlanner:
    """Synthesizes non-compliant audit findings into a prioritized, budgeted technical remediation roadmap."""

    HOURLY_ENGINEERING_RATE_EUR = 85.0

    @classmethod
    def plan_remediations(cls, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        failed = [f for f in findings if not f.get("passed", False)]
        actions: List[RemediationAction] = []

        cost_multipliers = {
            "CRITICAL": (16.0, True, True),   # 16 hours, auto-eligible with HITL
            "HIGH": (8.0, True, True),         # 8 hours
            "MEDIUM": (4.0, True, False),      # 4 hours, direct auto
            "LOW": (2.0, True, False)          # 2 hours
        }

        total_hours = 0.0
        total_cost = 0.0

        for i, finding in enumerate(failed, 1):
            sev = finding.get("severity", "MEDIUM")
            hours, auto_ok, needs_hitl = cost_multipliers.get(sev, (4.0, False, True))
            cost = hours * cls.HOURLY_ENGINEERING_RATE_EUR
            total_hours += hours
            total_cost += cost

            actions.append(RemediationAction(
                action_id=f"REM-{finding.get('framework', 'GEN')}-{i:03d}",
                rule_id=finding.get("rule_id", "RULE-UNKNOWN"),
                framework=finding.get("framework", "GENERAL"),
                title=f"Remediación Técnica: {finding.get('title', 'Control Insuficiente')}",
                priority=sev,
                estimated_hours=hours,
                estimated_cost_eur=cost,
                assigned_role="Lead Security Engineer / DevSecOps",
                automation_eligible=auto_ok,
                requires_hitl=needs_hitl,
                remediation_steps=[
                    f"Ejecutar script de remediación técnica conforme a la guía: {finding.get('remediation_guidance', 'Aplicar control estándar')}",
                    "Verificar no regresión en los tests de conformidad correspondientes.",
                    "Registrar evidencia sellada en el Merkle Bunker."
                ]
            ))

        return {
            "total_gaps": len(failed),
            "total_estimated_hours": total_hours,
            "total_estimated_cost_eur": total_cost,
            "remediation_actions": [asdict_rem(a) for a in actions]
        }

def asdict_rem(a: RemediationAction) -> Dict[str, Any]:
    return {
        "action_id": a.action_id,
        "rule_id": a.rule_id,
        "framework": a.framework,
        "title": a.title,
        "priority": a.priority,
        "estimated_hours": a.estimated_hours,
        "estimated_cost_eur": a.estimated_cost_eur,
        "assigned_role": a.assigned_role,
        "automation_eligible": a.automation_eligible,
        "requires_hitl": a.requires_hitl,
        "remediation_steps": a.remediation_steps
    }
