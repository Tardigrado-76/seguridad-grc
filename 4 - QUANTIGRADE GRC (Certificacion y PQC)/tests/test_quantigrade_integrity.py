"""
Integrity and TDD Unit Tests for QUANTIGRADE GCR Enterprise.
Verifies Air-Gap Armor, Core Mesh Imports, CLI invocation, and Regulatory Modules.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_core_mesh_imports():
    """Verify that core_mesh business execution, agentic wargame, and security modules import cleanly."""
    sys.path.insert(0, str(ROOT_DIR))
    from core_mesh.agentic.regulatory_war_game import RegulatoryWarGame
    from core_mesh.business_execution import (
        DynamicHolographicQR,
        EditorialPDFGenerator,
        EnterpriseRiskRegister,
        EvidenceSeal,
        MerkleBunker,
    )
    from core_mesh.operational.airgap_armor import AirGapArmorSentinel

    assert RegulatoryWarGame is not None
    assert DynamicHolographicQR is not None
    assert EditorialPDFGenerator is not None
    assert EnterpriseRiskRegister is not None
    assert EvidenceSeal is not None
    assert MerkleBunker is not None
    sentinel = AirGapArmorSentinel()
    telemetry = sentinel.get_telemetry()
    assert telemetry.status in ("ARMOR_ACTIVE_100_AIRGAPPED", "ARMOR_BREACHED_OUTBOUND_DETECTED")
    assert telemetry.outbound_calls_count >= 0

def test_cli_airgap_command():
    """Verify CLI airgap command executes cleanly in JSON mode."""
    cmd = [sys.executable, str(ROOT_DIR / "quantigrade_cli.py"), "airgap", "--json"]
    res = subprocess.run(cmd, cwd=str(ROOT_DIR), capture_output=True, text=True, check=False)
    assert res.returncode == 0
    assert "status" in res.stdout

def test_cli_scan_command():
    """Verify CLI scan command executes cleanly in JSON mode."""
    cmd = [sys.executable, str(ROOT_DIR / "quantigrade_cli.py"), "scan", "--json"]
    res = subprocess.run(cmd, cwd=str(ROOT_DIR), capture_output=True, text=True, check=False)
    assert res.returncode == 0
    assert "frameworks" in res.stdout
