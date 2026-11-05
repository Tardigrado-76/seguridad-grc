"""
Security Audit Suite: test_fastapi.py
Validates real CISA KEV supply chain requirements parser.
"""

from pathlib import Path
import pytest
import sys

_AUDIT_DIR = str(Path(__file__).resolve().parent.parent)
if _AUDIT_DIR not in sys.path:
    sys.path.insert(0, _AUDIT_DIR)

from check_cisa_kev import parse_requirements


def test_parse_requirements_valid(tmp_path):
    """Verify parsing valid requirements file extracts package names cleanly."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "# Production dependencies\n"
        "fastapi==0.115.0\n"
        "uvicorn>=0.30.0\n"
        "cryptography~=43.0.1\n"
        "pydantic[email]>=2.9.0\n",
        encoding="utf-8"
    )

    deps = parse_requirements(req_file)
    assert "fastapi" in deps
    assert "uvicorn" in deps
    assert "cryptography" in deps
    assert "pydantic" in deps
    assert len(deps) == 4


def test_parse_requirements_nonexistent(tmp_path):
    """Verify missing file returns empty list safely without crashing."""
    deps = parse_requirements(tmp_path / "nonexistent_requirements.txt")
    assert deps == []
