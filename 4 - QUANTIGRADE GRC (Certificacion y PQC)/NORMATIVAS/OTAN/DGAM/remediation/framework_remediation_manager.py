#!/usr/bin/env python3
"""
framework_remediation_manager.py - Remediation Layer Manager for DGAM_PECAL_DEFENSA_ES.
Synthesizes findings into prioritized defense roadmaps, executes auto-remediations, and guards with HITL.
"""

from __future__ import annotations

import sys
from pathlib import Path

GCR_ROOT = Path(r"E:/PROYECTOS IA/GCR")
if str(GCR_ROOT) not in sys.path:
    sys.path.insert(0, str(GCR_ROOT))

from core_mesh.remediation import (
    AutoRemediator,
    HITLApprovalGate,
    RemediationPlanner,
    RollbackEngine,
)


class FrameworkRemediationManager:
    def __init__(self):
        self.framework_id = "DGAM_PECAL_DEFENSA_ES"
        self.hitl_gate = HITLApprovalGate()
        self.auto_remediator = AutoRemediator()
        self.rollback_engine = RollbackEngine()

    def generate_plan(self, findings: list[dict]) -> dict:
        """Generates a prioritized remediation roadmap with estimated hours and cost."""
        return RemediationPlanner.plan_remediations(findings)

    def execute_fix(self, action_type: str, context: dict, requires_hitl: bool = True, officer_id: str = "DGAM_SECURITY_OFFICER") -> dict:
        """Executes an automated defense remediation or routes it through HITL approval."""
        if requires_hitl:
            req = self.hitl_gate.submit_request(
                action_id=f"REM-{self.framework_id}-ACT",
                framework=self.framework_id,
                description=f"Defense critical remediation: {action_type}",
                impact_level="CRITICAL"
            )
            decision = self.hitl_gate.decide(req.request_id, approved=True, officer_id=officer_id, comments="Approved by DGAM Security Officer")
            return {"hitl_approval": decision, "remediation": self.auto_remediator.execute_remediation(action_type, context)}
        return {"remediation": self.auto_remediator.execute_remediation(action_type, context)}

if __name__ == "__main__":
    manager = FrameworkRemediationManager()
    plan = manager.generate_plan([
        {"rule_id": "ES-DGAM-PECAL-001", "framework": "DGAM_PECAL_DEFENSA_ES", "title": "PECAL Gap", "severity": "CRITICAL", "passed": False, "remediation_guidance": "Implement PACS"}
    ])
    print("DGAM Plan:", plan)
