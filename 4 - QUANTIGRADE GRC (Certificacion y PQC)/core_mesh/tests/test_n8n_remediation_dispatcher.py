"""
Tests for N8nRemediationDispatcher: Zero-Docker n8n integration with HMAC-SHA256 signatures.
"""
import pytest
from core_mesh.remediation.n8n_remediation_dispatcher import (
    N8nRemediationDispatcher,
    RemediationDispatchResult,
)


def test_prepare_and_sign_payload():
    dispatcher = N8nRemediationDispatcher(webhook_url="http://localhost:5678/webhook/grc", secret_key="n8n_secret_123")
    payload = {"service": "AWS_IAM", "action": "REVOKE_UNUSED_CREDENTIALS", "user": "admin_temp"}

    signed_pkg = dispatcher.prepare_signed_payload("TASK-001", "REVOKE_KEYS", payload)
    assert signed_pkg["task_id"] == "TASK-001"
    assert signed_pkg["action_name"] == "REVOKE_KEYS"
    assert "hmac_signature" in signed_pkg
    assert len(signed_pkg["hmac_signature"]) == 64  # SHA-256 hex length


def test_verify_callback_signature():
    dispatcher = N8nRemediationDispatcher(webhook_url="http://localhost:5678/webhook/grc", secret_key="n8n_secret_123")
    payload = {"task_id": "TASK-001", "status": "COMPLETED", "execution_id": "exec_9988"}
    
    # Valid signature
    valid_sig = dispatcher.compute_signature(payload)
    assert dispatcher.verify_callback_signature(payload, valid_sig) is True

    # Invalid signature
    assert dispatcher.verify_callback_signature(payload, "invalid_sig_000000000000000000000000000000000000000000000000000000000000") is False


def test_dispatch_task_simulation():
    dispatcher = N8nRemediationDispatcher(webhook_url="http://localhost:5678/webhook/grc", secret_key="n8n_secret_123")
    result = dispatcher.dispatch_task(
        task_id="TASK_JIRA_01",
        action_name="CREATE_DORA_REMEDIATION_TICKET",
        payload={"summary": "Cifrado insuficiente en S3 bucket", "priority": "High"},
        simulate=True
    )

    assert result.success is True
    assert result.task_id == "TASK_JIRA_01"
    assert "SIMULATED_DISPATCH" in result.message
    assert len(result.receipt_hash) == 64
