import json
import pytest
from core_mesh.operational.headless_gcr_api import HeadlessGCRServer

def test_public_health_and_trust_badge():
    server = HeadlessGCRServer()
    status_code, body = server.handle_request("GET", "/api/v1/health")
    assert status_code == 200
    assert body["status"] == "HEALTHY"

    status_code_badge, body_badge = server.handle_request("GET", "/api/v1/trust/badge")
    assert status_code_badge == 200
    assert body_badge["badge"] == "QUANTIGRADE_VERIFIED"
    assert body_badge["frameworks_covered"] == 20

def test_protected_endpoint_requires_api_key():
    server = HeadlessGCRServer()
    # No header provided
    status_code, body = server.handle_request("POST", "/api/v1/audit/inspect", headers={})
    assert status_code == 401
    assert body["error"] == "UNAUTHORIZED"

def test_audit_inspect_with_valid_key():
    server = HeadlessGCRServer(admin_api_key="my_secret_token_123")
    headers = {"X-Quantigrade-Key": "my_secret_token_123"}
    payload = {"repo_url": "github.com/enterprise/backend", "framework": "DORA"}

    status_code, body = server.handle_request("POST", "/api/v1/audit/inspect", headers=headers, body=payload)
    assert status_code == 200
    assert body["status"] == "PASSED"
    assert body["score"] == 100.0
    assert len(body["merkle_seal"]) == 64

def test_council_deliberate_via_api():
    server = HeadlessGCRServer()
    headers = {"X-Quantigrade-Key": server.admin_api_key}
    incident = {"title": "Fuga de tokens JWT", "severity": "HIGH", "framework": "DORA"}

    status_code, body = server.handle_request("POST", "/api/v1/council/deliberate", headers=headers, body=incident)
    assert status_code == 200
    assert body["final_verdict"] == "REMEDIATION_PLAN_APPROVED"
    assert len(body["todos"]) == 3

def test_webhook_signing_and_verification():
    server = HeadlessGCRServer(webhook_secret="sec_hmac_key_test_123")
    evt_data = {"alert": "DORA compliance 100%", "timestamp": 12345678}
    envelope = server.generate_webhook_payload("COMPLIANCE_PASSED", evt_data)

    headers = envelope["headers"]
    sig_header = headers["X-Quantigrade-Signature"]
    raw_payload_bytes = json.dumps(envelope["payload"], sort_keys=True).encode("utf-8")

    # Valid check
    assert server.verify_webhook_signature(raw_payload_bytes, sig_header) is True

    # Tampered payload check
    tampered_bytes = json.dumps({"alert": "TAMPERED"}, sort_keys=True).encode("utf-8")
    assert server.verify_webhook_signature(tampered_bytes, sig_header) is False
