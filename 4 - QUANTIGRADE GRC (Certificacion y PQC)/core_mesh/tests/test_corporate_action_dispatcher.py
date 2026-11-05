import pytest
from core_mesh.remediation.corporate_action_dispatcher import CorporateActionDispatcher

def test_dispatch_github_pr():
    dispatcher = CorporateActionDispatcher()
    files = {"config/security.json": '{"enforce_tls": true}'}
    pr = dispatcher.dispatch_github_pr(
        repo="my-org/core-api",
        branch="fix/tls-13",
        title="Forzar TLS 1.3 en endpoints",
        description="Remediación automática para CRA Art. 10",
        file_patches=files
    )
    assert pr["type"] == "GITHUB_PULL_REQUEST"
    assert pr["repo"] == "my-org/core-api"
    assert "security" in pr["labels"]
    assert len(pr["payload_hash"]) == 64
    assert pr["dry_run"] is True

def test_dispatch_jira_issue():
    dispatcher = CorporateActionDispatcher()
    issue = dispatcher.dispatch_jira_issue(
        project_key="COMPLIANCE",
        summary="Brecha BOLA en /accounts/{id}",
        description="Falta validación de tenant.",
        priority="Highest"
    )
    assert issue["type"] == "JIRA_ISSUE"
    assert issue["project_key"] == "COMPLIANCE"
    assert "[GCR]" in issue["summary"]
    assert "dora-nis2" in issue["labels"]
    assert len(issue["payload_hash"]) == 64

def test_dispatch_slack_alert():
    dispatcher = CorporateActionDispatcher()
    slack = dispatcher.dispatch_slack_alert(
        channel="#sec-ops",
        finding_title="Algoritmo JWT 'none' detectado",
        severity="CRITICAL",
        framework="DORA TLPT",
        remediation_steps="Configurar claves RS256 de inmediato."
    )
    assert slack["type"] == "SLACK_ALERT"
    assert slack["channel"] == "#sec-ops"
    assert any(":rotating_light:" in block.get("text", {}).get("text", "") for block in slack["blocks"])
    assert len(slack["payload_hash"]) == 64

def test_generate_confluence_page():
    dispatcher = CorporateActionDispatcher()
    evidence = [
        {"control": "NIS2-MFA", "status": "Compliant", "hash": "a1b2c3d4e5f67890", "passed": True},
        {"control": "DORA-TLPT", "status": "Warning", "hash": "f6e5d4c3b2a10987", "passed": False}
    ]
    page = dispatcher.generate_confluence_page(
        space_key="AUDIT",
        page_title="Informe Mensual de Cumplimiento",
        executive_summary="Resumen de evaluación de riesgos.",
        evidence_table=evidence
    )
    assert page["type"] == "CONFLUENCE_DOCUMENTATION"
    assert page["total_controls_documented"] == 2
    assert "| NIS2-MFA | Compliant |" in page["content"]
    assert "✅ PASSED" in page["content"]
    assert "❌ FAILED" in page["content"]
    assert len(page["payload_hash"]) == 64

def test_route_compliance_finding_routing_logic():
    dispatcher = CorporateActionDispatcher()
    
    # Critical finding
    crit_finding = {
        "title": "Fuga de claves privadas",
        "severity": "CRITICAL",
        "framework": "ENS Categoría ALTA",
        "remediation": "Rotar credenciales inmediatamente."
    }
    dispatches_crit = dispatcher.route_compliance_finding(crit_finding)
    assert len(dispatches_crit) == 3
    types_crit = [d["type"] for d in dispatches_crit]
    assert "SLACK_ALERT" in types_crit
    assert "JIRA_ISSUE" in types_crit
    assert "GITHUB_PULL_REQUEST" in types_crit

    # Medium finding
    med_finding = {
        "title": "Cabecera HSTS expirada",
        "severity": "MEDIUM",
        "framework": "DORA",
        "remediation": "Extender max-age a 31536000."
    }
    dispatches_med = dispatcher.route_compliance_finding(med_finding)
    assert len(dispatches_med) == 1
    assert dispatches_med[0]["type"] == "JIRA_ISSUE"
