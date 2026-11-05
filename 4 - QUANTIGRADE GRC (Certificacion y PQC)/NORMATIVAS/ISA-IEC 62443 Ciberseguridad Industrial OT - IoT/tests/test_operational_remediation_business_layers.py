#!/usr/bin/env python3
"""Test suite for Operational, Remediation, and Business Execution layers of ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT."""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
FRAMEWORK_ROOT = CURRENT_DIR.parent
GCR_ROOT = FRAMEWORK_ROOT.parents[0]

for p in [FRAMEWORK_ROOT, GCR_ROOT]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from business_execution.framework_business_executive import FrameworkBusinessExecutive
from operational.framework_runtime_monitor import FrameworkRuntimeMonitor
from remediation.framework_remediation_manager import FrameworkRemediationManager


def test_operational_layer_isa_iec_62443():
    monitor = FrameworkRuntimeMonitor()
    res = monitor.monitor_transaction("Instruccion Modbus TCP en PLC para Operador DNI 66778899F")
    assert "[REDACTED_DNI_NIE]" in res["sanitized_payload"]
    assert res["telemetry_event"]["status"] == "SUCCESS"

def test_remediation_layer_isa_iec_62443():
    mgr = FrameworkRemediationManager()
    plan = mgr.generate_plan([
        {"rule_id": "IEC-62443-ZONES-001", "framework": "ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT", "title": "Zones Gap", "severity": "CRITICAL", "passed": False}
    ])
    assert plan["total_gaps"] == 1
    assert plan["total_estimated_hours"] > 0
    fix = mgr.execute_fix("TLS_UPGRADE", {"target": "plc_modbus_gateway"}, requires_hitl=True)
    assert fix["hitl_approval"]["status"] == "APPROVED"
    assert fix["remediation"]["status"] == "SUCCESS"

def test_business_execution_layer_isa_iec_62443():
    biz = FrameworkBusinessExecutive()
    gov = biz.execute_business_governance(compliance_score=100.0, rag_status="GREEN", total_rules=4, passed_rules=4)
    assert gov["seal"].merkle_root is not None
    assert gov["seal"].leaf_count > 0
    assert "Dictamen Ejecutivo" in gov["dictamen_markdown"]
    assert gov["financial_exposure"]["residual_risk_eur"] == 0.0
