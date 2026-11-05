"""
Test suite for AuditorTokenGuard (Read-Only Ephemeral Auditor Portal).
Validates token issuance, expiration, scope restrictions, and tamper detection.
"""

import time
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core_mesh.operational.auditor_token_guard import AuditorTokenGuard, AuditorSession


def test_auditor_token_issuance_and_verification():
    guard = AuditorTokenGuard(secret_key="AUDITOR_PORTAL_TEST_SECRET_KEY_123")
    
    token = guard.create_token(
        auditor_id="AUD-CNMV-99",
        organization="CNMV / BdE Oversight",
        validity_seconds=3600,
        allowed_frameworks=["DORA", "Ciberresiliencia Financiera en España", "ENS"]
    )
    assert token is not None
    assert token.startswith("aud_tok_")
    
    session = guard.verify_token(token)
    assert session is not None
    assert isinstance(session, AuditorSession)
    assert session.auditor_id == "AUD-CNMV-99"
    assert session.organization == "CNMV / BdE Oversight"
    assert session.is_read_only is True
    assert "DORA" in session.allowed_frameworks
    assert session.can_execute_remediation is False


def test_auditor_token_expiration():
    guard = AuditorTokenGuard(secret_key="AUDITOR_PORTAL_TEST_SECRET_KEY_123")
    
    # Create token that expired 10 seconds ago
    token = guard.create_token(
        auditor_id="AUD-EXP-01",
        organization="Expired Session Test",
        validity_seconds=-10
    )
    session = guard.verify_token(token)
    assert session is None  # Expired tokens must be rejected


def test_auditor_token_tamper_detection():
    guard = AuditorTokenGuard(secret_key="AUDITOR_PORTAL_TEST_SECRET_KEY_123")
    token = guard.create_token("AUD-TAMPER-01", "AENOR ISO Lead Auditor", 3600)
    
    # Corrupt token parts
    parts = token.split(".")
    assert len(parts) == 3
    tampered_token = f"{parts[0]}.{parts[1]}.corrupted_signature_12345678"
    assert guard.verify_token(tampered_token) is None

    # Invalid secret key validation fails
    other_guard = AuditorTokenGuard(secret_key="UNAUTHORIZED_DIFFERENT_KEY")
    assert other_guard.verify_token(token) is None
