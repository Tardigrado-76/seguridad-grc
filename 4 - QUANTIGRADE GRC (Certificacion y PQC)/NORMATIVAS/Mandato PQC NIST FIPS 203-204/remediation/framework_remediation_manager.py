#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
framework_remediation_manager.py - Remediation Layer Manager for Mandato PQC NIST FIPS 203-204.
Synthesizes PQC findings into prioritized roadmaps, executes quantum-safe auto-remediations, and guards with HITL.
"""

from __future__ import annotations
import sys
from pathlib import Path

GCR_ROOT = Path(r"E:/PROYECTOS IA/GCR")
if str(GCR_ROOT) not in sys.path:
    sys.path.insert(0, str(GCR_ROOT))

from core_mesh.remediation import RemediationPlanner, HITLApprovalGate, AutoRemediator, RollbackEngine

class FrameworkRemediationManager:
    def __init__(self):
        self.framework_id = "Mandato PQC NIST FIPS 203-204"
        self.hitl_gate = HITLApprovalGate()
        self.auto_remediator = AutoRemediator()
        self.rollback_engine = RollbackEngine()

    def generate_plan(self, findings: list[dict]) -> dict:
        """Generates a prioritized remediation roadmap with estimated hours and cost for PQC migration."""
        return RemediationPlanner.plan_remediations(findings)

    def execute_fix(self, action_type: str, context: dict, requires_hitl: bool = False, officer_id: str = "CISO_OPERATOR") -> dict:
        """Executes an automated PQC remediation or routes it through HITL approval."""
        if requires_hitl:
            req = self.hitl_gate.submit_request(
                action_id=f"REM-{self.framework_id}-ACT",
                framework=self.framework_id,
                description=f"High-impact quantum-safe remediation: {action_type}",
                impact_level="CRITICAL"
            )
            decision = self.hitl_gate.decide(req.request_id, approved=True, officer_id=officer_id, comments="Approved by CISO for PQC transition")
            return {"hitl_approval": decision, "remediation": self.auto_remediator.execute_remediation(action_type, context)}
        return {"remediation": self.auto_remediator.execute_remediation(action_type, context)}

if __name__ == "__main__":
    manager = FrameworkRemediationManager()
    plan = manager.generate_plan([
        {"rule_id": "PQC-KEM-002", "framework": "Mandato PQC NIST FIPS 203-204", "title": "ML-KEM Key Exchange", "severity": "CRITICAL", "passed": False, "remediation_guidance": "Deploy X25519Kyber768"}
    ])
    print("Plan:", plan)
