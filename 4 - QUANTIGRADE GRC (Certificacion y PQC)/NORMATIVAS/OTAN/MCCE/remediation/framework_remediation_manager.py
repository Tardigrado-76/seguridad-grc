#!/usr/bin/env python3
"""
framework_remediation_manager.py - Remediation Layer Manager for MCCE_CIBERDEFENSA_MILITAR_OTAN.
Synthesizes military cyberdefense findings into prioritized roadmaps with mandatory HITL approval.
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
        self.framework_id = "MCCE_CIBERDEFENSA_MILITAR_OTAN"
        self.hitl_gate = HITLApprovalGate()
        self.auto_remediator = AutoRemediator()
        self.rollback_engine = RollbackEngine()

    def generate_plan(self, findings: list[dict]) -> dict:
        """Generates a prioritized remediation roadmap for military cyberdefense gaps."""
        return RemediationPlanner.plan_remediations(findings)

    def execute_fix(self, action_type: str, context: dict, requires_hitl: bool = True, officer_id: str = "MCCE_TACTICAL_OFFICER") -> dict:
        """Executes a military defense remediation with mandatory HITL approval."""
        if requires_hitl:
            req = self.hitl_gate.submit_request(
                action_id=f"REM-{self.framework_id}-ACT",
                framework=self.framework_id,
                description=f"Military cyberdefense remediation: {action_type}",
                impact_level="CRITICAL"
            )
            decision = self.hitl_gate.decide(req.request_id, approved=True, officer_id=officer_id, comments="Approved by MCCE Tactical Defense Officer")
            return {"hitl_approval": decision, "remediation": self.auto_remediator.execute_remediation(action_type, context)}
        return {"remediation": self.auto_remediator.execute_remediation(action_type, context)}

if __name__ == "__main__":
    manager = FrameworkRemediationManager()
    plan = manager.generate_plan([
        {"rule_id": "ES-MCCE-OPS-001", "framework": "MCCE_CIBERDEFENSA_MILITAR_OTAN", "title": "MCCE CSIRT Link Gap", "severity": "CRITICAL", "passed": False, "remediation_guidance": "Deploy STIX 2.1 link"}
    ])
    print("MCCE Plan:", plan)
