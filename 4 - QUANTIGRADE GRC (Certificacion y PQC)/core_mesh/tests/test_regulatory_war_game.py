#!/usr/bin/env python3
"""
test_regulatory_war_game.py - TDD Suite for RegulatoryWarGame.
Verifies scenario cataloging, deterministic real evidence matching, and scoring logic.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from core_mesh.agentic.regulatory_war_game import SCENARIOS_CATALOG, RegulatoryWarGame


def test_scenarios_catalog_complete():
    wargame = RegulatoryWarGame()
    scenarios = wargame.list_scenarios()
    assert len(scenarios) == len(SCENARIOS_CATALOG)
    ids = [s["scenario_id"] for s in scenarios]
    assert "WAR-CCN-001" in ids
    assert "WAR-DGAM-002" in ids
    assert "WAR-ITAR-003" in ids
    assert "WAR-AEPD-004" in ids
    assert "WAR-DORA-005" in ids


def test_evaluate_inspection_with_missing_evidences():
    with tempfile.TemporaryDirectory() as tmp_dir:
        wargame = RegulatoryWarGame(gcr_root=Path(tmp_dir))
        result = wargame.evaluate_inspection("WAR-CCN-001")
        assert result["readiness_score"] == 0.0
        assert result["verdict"] == "INSPECCION_FALLIDA"
        assert len(result["missing_patterns"]) == 4


def test_evaluate_inspection_with_complete_evidences():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # Create matching evidence files
        (tmp_path / "fim_integrity_log.json").write_text("{\"integrity\": true}", encoding="utf-8")
        (tmp_path / "ines_ccn_report.json").write_text("{\"status\": \"READY\"}", encoding="utf-8")
        (tmp_path / "lucia_csirt_stix.json").write_text("{\"stix\": true}", encoding="utf-8")
        (tmp_path / "ens_alta_audit.md").write_text("# ENS ALTA", encoding="utf-8")

        wargame = RegulatoryWarGame(gcr_root=tmp_path)
        result = wargame.evaluate_inspection("WAR-CCN-001")
        assert result["readiness_score"] == 100.0
        assert result["verdict"] == "APROBADO_CON_EXCELENCIA"
        assert len(result["found_evidences"]) == 4
        assert len(result["missing_patterns"]) == 0
        assert len(result["merkle_inspection_proof"]) == 64
