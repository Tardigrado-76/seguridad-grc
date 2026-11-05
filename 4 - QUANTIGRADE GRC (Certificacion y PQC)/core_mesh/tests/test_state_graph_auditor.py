"""
Tests for StateGraphAuditor: Deterministic state graph execution with SQLite checkpointing.
"""
import pytest
from core_mesh.agentic.state_graph_auditor import (
    StateGraphAuditor,
    GraphState,
    NodeResult,
)


def step_check_perimeter(state: GraphState) -> NodeResult:
    # Simulates perimetral scan
    found_open_ports = state.context.get("open_ports", [])
    if len(found_open_ports) > 0:
        return NodeResult(next_node="DEEP_FORENSIC_SCAN", updates={"anomaly_detected": True})
    return NodeResult(next_node="CHECK_IAM", updates={"perimeter_clean": True})


def step_deep_scan(state: GraphState) -> NodeResult:
    return NodeResult(next_node="FINALIZE_AUDIT", updates={"forensic_report_generated": True})


def step_check_iam(state: GraphState) -> NodeResult:
    return NodeResult(next_node="FINALIZE_AUDIT", updates={"iam_verified": True})


def test_state_graph_auditor_linear_flow(tmp_path):
    db_file = str(tmp_path / "test_graph.db")
    auditor = StateGraphAuditor(checkpoint_db_path=db_file)

    auditor.add_node("START", step_check_perimeter)
    auditor.add_node("CHECK_IAM", step_check_iam)
    auditor.add_node("DEEP_FORENSIC_SCAN", step_deep_scan)

    # Initial state with no open ports -> should go to CHECK_IAM -> FINALIZE_AUDIT
    final_state = auditor.execute(initial_node="START", initial_context={"open_ports": []})

    assert final_state.current_node == "FINALIZE_AUDIT"
    assert final_state.context.get("perimeter_clean") is True
    assert final_state.context.get("iam_verified") is True
    assert "DEEP_FORENSIC_SCAN" not in final_state.execution_path


def test_state_graph_auditor_branching_on_anomaly(tmp_path):
    db_file = str(tmp_path / "test_graph_branch.db")
    auditor = StateGraphAuditor(checkpoint_db_path=db_file)

    auditor.add_node("START", step_check_perimeter)
    auditor.add_node("CHECK_IAM", step_check_iam)
    auditor.add_node("DEEP_FORENSIC_SCAN", step_deep_scan)

    # Initial state with open ports -> should branch to DEEP_FORENSIC_SCAN
    final_state = auditor.execute(initial_node="START", initial_context={"open_ports": [22, 3389]})

    assert final_state.current_node == "FINALIZE_AUDIT"
    assert final_state.context.get("anomaly_detected") is True
    assert final_state.context.get("forensic_report_generated") is True
    assert "DEEP_FORENSIC_SCAN" in final_state.execution_path


def test_state_graph_auditor_checkpoint_persistence(tmp_path):
    db_file = str(tmp_path / "test_checkpoint.db")
    auditor = StateGraphAuditor(checkpoint_db_path=db_file)

    auditor.add_node("START", step_check_perimeter)
    auditor.add_node("CHECK_IAM", step_check_iam)
    auditor.add_node("DEEP_FORENSIC_SCAN", step_deep_scan)

    auditor.execute(initial_node="START", initial_context={"open_ports": [8080]})
    
    # Verify records stored in SQLite WAL
    checkpoints = auditor.get_checkpoints()
    assert len(checkpoints) >= 2
    assert checkpoints[0]["node_name"] == "START"
