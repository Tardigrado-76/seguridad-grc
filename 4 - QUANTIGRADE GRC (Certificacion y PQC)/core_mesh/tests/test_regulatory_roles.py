"""
Tests for RegulatoryRoleRegistry: Separation of duties and regulatory agent archetypes.
"""
import pytest
from core_mesh.agentic.regulatory_roles import (
    RegulatoryRoleRegistry,
    RoleSpecification,
    RoleActionDecision,
)


def test_registered_archetypes_exist():
    registry = RegulatoryRoleRegistry()
    roles = registry.get_registered_roles()
    assert "CISO" in roles
    assert "DPO" in roles
    assert "INTERNAL_AUDITOR" in roles
    assert "RED_TEAMER" in roles


def test_separation_of_duties_red_team_cannot_approve_remediation():
    registry = RegulatoryRoleRegistry()
    # A Red Teamer discovers vulnerabilities but MUST NOT approve sign-offs
    decision = registry.validate_action(role_name="RED_TEAMER", action="APPROVE_REMEDIATION_SIGN_OFF")
    assert decision.is_authorized is False
    assert "separation of duties" in decision.reason.lower() or "unauthorized" in decision.reason.lower()


def test_separation_of_duties_dpo_cannot_waive_retention():
    registry = RegulatoryRoleRegistry()
    # DPO cannot waive statutory retention limits
    decision = registry.validate_action(role_name="DPO", action="WAIVE_GDPR_RETENTION_POLICY")
    assert decision.is_authorized is False


def test_authorized_ciso_action():
    registry = RegulatoryRoleRegistry()
    decision = registry.validate_action(role_name="CISO", action="TRIGGER_ISOLATION_HARNESS")
    assert decision.is_authorized is True


def test_role_system_prompt_generation():
    registry = RegulatoryRoleRegistry()
    prompt = registry.get_system_prompt("DPO")
    assert "RGPD" in prompt
    assert "privacidad" in prompt.lower()
    assert "mandato" in prompt.lower()
