#!/usr/bin/env python3
"""
test_quantigrade_cli.py - TDD Suite for quantigrade_cli.py (HKUDS CLI-Anything Standard).
Verifies subprocess execution, CLI argument parsing, clean exit codes, and structured JSON outputs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

CLI_SCRIPT = Path(__file__).resolve().parent.parent.parent / "quantigrade_cli.py"


def run_cli(*args: str) -> tuple[int, str, str]:
    cmd = [sys.executable, str(CLI_SCRIPT)] + list(args)
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_cli_scan_json_output():
    code, stdout, stderr = run_cli("scan", "--json")
    assert code == 0, f"CLI scan failed: {stderr}"
    data = json.loads(stdout)
    assert data["status"] == "SUCCESS"
    assert data["scanned_count"] >= 20
    assert data["compliance_score"] == 100.0


def test_cli_airgap_json_output():
    code, stdout, stderr = run_cli("airgap", "--json")
    assert code == 0, f"CLI airgap failed: {stderr}"
    data = json.loads(stdout)
    assert "armor_active" in data
    assert "outbound_calls_count" in data
    assert data["status"] == "ARMOR_ACTIVE_100_AIRGAPPED"


def test_cli_report_multilang_json_output():
    code, stdout, stderr = run_cli("report", "--framework", "DGAM", "--lang", "fr", "--json")
    assert code == 0, f"CLI report failed: {stderr}"
    data = json.loads(stdout)
    assert data["framework"] == "DGAM"
    assert data["language"] == "fr"
    assert len(data["merkle_root"]) == 64
    assert data["status"] == "SEALED"


def test_cli_wargame_json_output():
    code, stdout, stderr = run_cli("wargame", "--scenario", "WAR-CCN-001", "--json")
    assert code == 0, f"CLI wargame failed: {stderr}"
    data = json.loads(stdout)
    assert "readiness_score" in data
    assert "verdict" in data
    assert "merkle_inspection_proof" in data
