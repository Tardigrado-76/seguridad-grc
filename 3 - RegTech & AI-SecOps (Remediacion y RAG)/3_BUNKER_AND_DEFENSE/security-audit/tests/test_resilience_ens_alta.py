"""
Security Audit Suite: test_resilience_ens_alta.py
Validates real IAM Least Privilege & MFA Auditing under DORA Art. 9 & ENS Alta requirements.
"""

from pathlib import Path
import pytest
import sys

_AUDIT_DIR = str(Path(__file__).resolve().parent.parent)
if _AUDIT_DIR not in sys.path:
    sys.path.insert(0, _AUDIT_DIR)

from iam_privilege_auditor import DORAIAMPrivilegeAuditor, IAMUserAccount


def test_iam_auditor_detects_mfa_and_wildcard_violations():
    """Verify auditor detects unhardened admin accounts missing MFA and having wildcard permissions."""
    auditor = DORAIAMPrivilegeAuditor()
    auditor.add_account(IAMUserAccount(
        username="secops_admin",
        email="admin@enterprise.eu",
        role="DomainAdmin",
        is_privileged_account=True,
        mfa_enabled=False,
        last_login_days_ago=5,
        is_active=True,
        assigned_permissions=["*"],
        password_age_days=180
    ))

    report = auditor.evaluate_audit()

    assert report.total_accounts_scanned == 1
    assert report.admin_missing_mfa_count == 1
    assert report.excessive_privilege_count == 1
    assert report.dora_status in ["NO_CONFORME_RIESGO_CRITICO", "CRITICAL_RISK", "AT_RISK"]
    assert len(report.findings) >= 2


def test_iam_auditor_compliant_least_privilege_account():
    """Verify compliant account with MFA and least-privilege permissions receives 100% compliant score."""
    auditor = DORAIAMPrivilegeAuditor()
    auditor.add_account(IAMUserAccount(
        username="auditor_read_only",
        email="auditor@enterprise.eu",
        role="SecurityAuditor",
        is_privileged_account=False,
        mfa_enabled=True,
        last_login_days_ago=2,
        is_active=True,
        assigned_permissions=["logs:Read", "metrics:View"],
        password_age_days=30
    ))

    report = auditor.evaluate_audit()

    assert report.total_accounts_scanned == 1
    assert report.admin_missing_mfa_count == 0
    assert report.excessive_privilege_count == 0
    assert report.orphaned_accounts_count == 0
    assert report.dora_compliance_score == 100.0
    assert len(report.findings) == 0
