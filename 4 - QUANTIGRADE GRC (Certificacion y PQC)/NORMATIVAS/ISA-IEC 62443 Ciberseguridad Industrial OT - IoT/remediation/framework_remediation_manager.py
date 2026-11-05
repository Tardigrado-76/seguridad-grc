#!/usr/bin/env python3
"""
framework_remediation_manager.py - Remediation Layer Manager for ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT.
Synthesizes OT/IACS findings into prioritized roadmaps and controls automated interventions with HITL approval.
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
        self.framework_id = "ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT"
        self.hitl_gate = HITLApprovalGate()
        self.auto_remediator = AutoRemediator()
        self.rollback_engine = RollbackEngine()

    def generate_plan(self, findings: list[dict]) -> dict:
        """Generates a prioritized remediation roadmap for industrial cybersecurity findings."""
        return RemediationPlanner.plan_remediations(findings)

    def execute_fix(self, action_type: str, context: dict, requires_hitl: bool = True, officer_id: str = "OT_OPERATIONS_OFFICER") -> dict:
        """Executes an industrial OT remediation with mandatory HITL approval."""
        if requires_hitl:
            req = self.hitl_gate.submit_request(
                action_id=f"REM-{self.framework_id}-ACT",
                framework=self.framework_id,
                description=f"Industrial IACS remediation: {action_type}",
                impact_level="CRITICAL"
            )
            decision = self.hitl_gate.decide(req.request_id, approved=True, officer_id=officer_id, comments="Approved by OT Plant Operations Manager")
            return {"hitl_approval": decision, "remediation": self.auto_remediator.execute_remediation(action_type, context)}
        return {"remediation": self.auto_remediator.execute_remediation(action_type, context)}

if __name__ == "__main__":
    manager = FrameworkRemediationManager()
    plan = manager.generate_plan([
        {"rule_id": "IEC-62443-ZONES-001", "framework": "ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT", "title": "Zones Gap", "severity": "CRITICAL", "passed": False, "remediation_guidance": "Partition OT network"}
    ])
    print("IEC 62443 Plan:", plan)
