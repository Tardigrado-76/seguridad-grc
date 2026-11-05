"""Pytest shared fixtures for compliance engine tests."""
import pytest
from pathlib import Path
import tempfile
import os


@pytest.fixture
def temp_target(tmp_path) -> Path:
    """Creates a temp directory with sample compliance evidence files."""
    (tmp_path / "security_policy.md").write_text("# Security Policy v1.0")
    (tmp_path / "incident_handling.md").write_text("# Incident Response Procedure")
    (tmp_path / "asset_inventory.csv").write_text("id,name,level\n1,server-01,ALTA")
    (tmp_path / "tls_config.yaml").write_text("tls_version: 1.3")
    (tmp_path / "backup_integrity.log").write_text("backup verified OK")
    (tmp_path / "third_party_register.xlsx").write_text("supplier list")
    (tmp_path / "mfa_policy.pdf").write_text("MFA policy doc")
    return tmp_path