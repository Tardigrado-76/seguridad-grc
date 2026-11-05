import pytest
import sqlite3
from pathlib import Path
from core_mesh.agentic.airgapped_inspector import AirGappedInspector

def test_sqlite_trace_recording_and_integrity(tmp_path):
    db_file = str(tmp_path / "test_traces.db")
    inspector = AirGappedInspector(db_path=db_file, tenant_id="tenant_es_01")

    # Record two traces
    inspector.record_trace("CONFIG_SCAN", "config/tls.json", "SUCCESS", {"tls_version": "1.3"})
    inspector.record_trace("MFA_CHECK", "iam/policies.json", "SUCCESS", {"mfa_enforced": True})

    # Verify integrity
    report = inspector.verify_trace_integrity()
    assert report["verified"] is True
    assert report["total_records"] == 2
    assert report["status"] == "INTEGRITY_VERIFIED"

def test_tampered_trace_detected(tmp_path):
    db_file = str(tmp_path / "tamper_traces.db")
    inspector = AirGappedInspector(db_path=db_file, tenant_id="tenant_es_02")

    inspector.record_trace("AUDIT_1", "file1.txt", "SUCCESS", {"val": 1})
    inspector.record_trace("AUDIT_2", "file2.txt", "SUCCESS", {"val": 2})

    # Tamper with row 1 in SQLite
    conn = sqlite3.connect(db_file)
    conn.execute("UPDATE airgapped_traces SET action_name = 'HACKED' WHERE id = 1;")
    conn.commit()
    conn.close()

    tamper_report = inspector.verify_trace_integrity()
    assert tamper_report["verified"] is False
    assert tamper_report["status"] in ["HASH_MISMATCH", "CHAIN_BROKEN_AT_PREV_HASH"]

def test_fail_closed_gateway_blocks_missing_signature(tmp_path):
    db_file = str(tmp_path / "gateway_traces.db")
    inspector = AirGappedInspector(db_path=db_file)

    bad_action = {
        "action_id": "REM-01",
        "target_path": "config/tls.json",
        "remediation_code": "enforce_tls_13()",
        # Missing hitl_approval_signature
    }
    decision = inspector.evaluate_fail_closed_gateway(bad_action)
    assert decision["allowed"] is False
    assert decision["decision"] == "BLOCKED_FAIL_CLOSED"
    assert "Faltan credenciales/firmas" in decision["reason"]

def test_fail_closed_gateway_blocks_path_traversal(tmp_path):
    db_file = str(tmp_path / "gateway_traces2.db")
    inspector = AirGappedInspector(db_path=db_file)

    traversal_action = {
        "action_id": "REM-02",
        "target_path": "../../windows/system32/cmd.exe",
        "remediation_code": "del /f",
        "hitl_approval_signature": "a" * 64
    }
    decision = inspector.evaluate_fail_closed_gateway(traversal_action)
    assert decision["allowed"] is False
    assert decision["decision"] == "BLOCKED_FAIL_CLOSED"
    assert "Ruta fuera de los límites" in decision["reason"]

def test_fail_closed_gateway_allows_valid_remediation(tmp_path):
    db_file = str(tmp_path / "gateway_traces3.db")
    inspector = AirGappedInspector(db_path=db_file)

    valid_action = {
        "action_id": "REM-03",
        "target_path": "config/security_posture.json",
        "remediation_code": "enable_pqc_fips_204()",
        "hitl_approval_signature": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
    decision = inspector.evaluate_fail_closed_gateway(valid_action)
    assert decision["allowed"] is True
    assert decision["decision"] == "APPROVED_FOR_EXECUTION"
