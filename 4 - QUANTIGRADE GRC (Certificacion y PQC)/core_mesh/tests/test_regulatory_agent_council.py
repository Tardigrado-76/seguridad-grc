import pytest
from core_mesh.agentic.regulatory_agent_council import RegulatoryAgentCouncil

def test_council_roles_initialized():
    council = RegulatoryAgentCouncil()
    assert "CISO" in council.ROLES
    assert "DPO" in council.ROLES
    assert "RED_TEAM" in council.ROLES
    assert "CCO" in council.ROLES
    assert council.ROLES["CISO"]["risk_tolerance"] == "EXTREMELY_LOW"

def test_council_deliberation_critical_finding():
    council = RegulatoryAgentCouncil()
    finding = {
        "title": "Brecha BOLA en /api/v1/transferencias/{id}",
        "framework": "DORA Art. 26 TLPT",
        "severity": "CRITICAL",
        "details": "Acceso a balances de otros clientes sin autorización."
    }
    result = council.deliberate(finding)

    assert result["final_verdict"] == "REMEDIATION_PLAN_APPROVED"
    assert result["rounds"]["round_1_ciso"]["stance"] == "RECHAZO_TECNICO"
    assert result["rounds"]["round_3_red_team"]["exploitable"] is True
    assert len(result["todos"]) == 3
    assert result["todos"][0]["priority"] == "P0"
    assert len(result["debate_hash"]) == 64
    assert result["token_budget_consumed"] <= 500

def test_council_deliberation_pii_triggers_dpo():
    council = RegulatoryAgentCouncil()
    finding = {
        "title": "Exposición de DNI y correos de clientes en logs",
        "framework": "RGPD",
        "severity": "HIGH",
        "details": "Fuga de DNI en trazas de servidor."
    }
    result = council.deliberate(finding)
    dpo_round = result["rounds"]["round_2_dpo"]

    assert dpo_round["stance"] == "BLOQUEO_POR_RIESGO_RGPD"
    assert dpo_round["statutory_deadline_days"] == 30
    assert any("RGPD" in todo["framework"] for todo in result["todos"])

def test_council_session_history():
    council = RegulatoryAgentCouncil()
    council.deliberate({"title": "Finding 1", "severity": "MEDIUM"})
    council.deliberate({"title": "Finding 2", "severity": "LOW"})

    assert len(council.deliberation_history) == 2
    assert council.deliberation_history[0]["session_id"] != council.deliberation_history[1]["session_id"]
