#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test suite for Operational, Remediation, and Business Execution layers of DSA."""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
FRAMEWORK_ROOT = CURRENT_DIR.parent
GCR_ROOT = FRAMEWORK_ROOT.parent

for p in [FRAMEWORK_ROOT, GCR_ROOT]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from operational.framework_runtime_monitor import FrameworkRuntimeMonitor
from remediation.framework_remediation_manager import FrameworkRemediationManager
from business_execution.framework_business_executive import FrameworkBusinessExecutive

def test_operational_layer_dsa():
    monitor = FrameworkRuntimeMonitor()
    res = monitor.monitor_transaction("Usuario DNI 99887766A transaccionando en DSA")
    assert "[REDACTED_DNI_NIE]" in res["sanitized_payload"]
    assert res["telemetry_event"]["status"] == "SUCCESS"

def test_remediation_layer_dsa():
    mgr = FrameworkRemediationManager()
    plan = mgr.generate_plan([
        {"rule_id": "TEST-GAP-01", "framework": "DSA", "title": "Inspeccion", "severity": "HIGH", "passed": False}
    ])
    assert plan["total_gaps"] == 1
    assert plan["total_estimated_hours"] > 0
    fix = mgr.execute_fix("TLS_UPGRADE", {"target": "cluster"}, requires_hitl=True)
    assert fix["hitl_approval"]["status"] == "APPROVED"
    assert fix["remediation"]["status"] == "SUCCESS"

def test_business_execution_layer_dsa():
    biz = FrameworkBusinessExecutive()
    gov = biz.execute_business_governance(compliance_score=100.0, rag_status="GREEN", total_rules=4, passed_rules=4)
    assert gov["seal"].merkle_root is not None
    assert gov["seal"].leaf_count > 0
    assert "Dictamen Ejecutivo" in gov["dictamen_markdown"]
    assert gov["financial_exposure"]["residual_risk_eur"] == 0.0
