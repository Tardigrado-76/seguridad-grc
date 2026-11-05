"""
Test suite for GitSecurityMesh connector.
Validates git repository auditing, lockfile detection, secret scanning, and security scoring.
"""

import sys
import tempfile
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
from core_mesh.operational.git_security_mesh import GitSecurityMesh, GitAuditReport


def test_git_security_mesh_scans_clean_repo():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # Create standard secure setup: lockfile, dependabot, .gitignore
        (tmp_path / ".gitignore").write_text("*.env\n*.pem\n__pycache__/\n", encoding="utf-8")
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text("version: 2\nupdates:\n  - package-ecosystem: 'pip'\n", encoding="utf-8")
        (tmp_path / "poetry.lock").write_text("# poetry lockfile\n", encoding="utf-8")
        (tmp_path / "main.py").write_text("print('Hello secure world')\n", encoding="utf-8")

        scanner = GitSecurityMesh()
        report = scanner.audit_repository(tmp_path)

        assert isinstance(report, GitAuditReport)
        assert report.has_gitignore is True
        assert report.has_dependency_lockfile is True
        assert report.has_automated_security_updates is True
        assert report.secrets_found == 0
        assert report.security_score >= 80.0


def test_git_security_mesh_detects_leaked_secrets_and_missing_guards():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # Insecure repo: has hardcoded AWS secret and private key, no lockfile, no gitignore
        (tmp_path / "config.py").write_text(
            "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
            "API_KEY = 'sk-proj-1234567890abcdef1234567890abcdef12345678'\n",
            encoding="utf-8"
        )
        (tmp_path / "server.key").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...", encoding="utf-8")

        scanner = GitSecurityMesh()
        report = scanner.audit_repository(tmp_path)

        assert report.has_gitignore is False
        assert report.has_dependency_lockfile is False
        assert report.secrets_found >= 2
        assert report.security_score < 50.0
        assert len(report.findings) >= 2
