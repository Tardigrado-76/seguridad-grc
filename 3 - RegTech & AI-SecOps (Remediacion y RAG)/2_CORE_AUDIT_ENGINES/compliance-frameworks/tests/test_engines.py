"""Unit tests for compliance engines — target coverage >= 85%."""
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from engines.dora_engine import DORAEngine
from engines.nis2_engine import NIS2Engine
from engines.ens_engine import ENSEngine


class TestDORAEngine:
    def test_run_returns_report_structure(self, temp_target, tmp_path):
        engine = DORAEngine(target_path=str(temp_target))
        report = engine.run()
        assert "engine" in report
        assert report["engine"] == "dora"
        assert "score" in report
        assert "results" in report
        assert isinstance(report["results"], list)
        assert len(report["results"]) == 10

    def test_score_is_percentage(self, temp_target):
        engine = DORAEngine(target_path=str(temp_target))
        report = engine.run()
        assert 0.0 <= report["score"] <= 100.0

    def test_all_checks_have_status(self, temp_target):
        engine = DORAEngine(target_path=str(temp_target))
        report = engine.run()
        for r in report["results"]:
            assert r["status"] in ("PASS", "FAIL")
            assert "id" in r
            assert "critical" in r


class TestNIS2Engine:
    def test_run_returns_report(self, temp_target):
        engine = NIS2Engine(target_path=str(temp_target))
        report = engine.run()
        assert report["engine"] == "nis2"
        assert len(report["results"]) == 9

    def test_detects_mfa_evidence(self, temp_target):
        engine = NIS2Engine(target_path=str(temp_target))
        report = engine.run()
        mfa_check = next(r for r in report["results"] if "ART21-05" in r["id"])
        assert mfa_check["status"] == "PASS"  # temp_target has mfa_policy.pdf


class TestENSEngine:
    def test_run_returns_report(self, temp_target):
        engine = ENSEngine(target_path=str(temp_target))
        report = engine.run()
        assert report["engine"] == "ens"
        assert len(report["results"]) == 10

    def test_clara_check_fails_without_evidence(self, tmp_path):
        engine = ENSEngine(target_path=str(tmp_path))
        report = engine.run()
        clara = next(r for r in report["results"] if "CLARA" in r["id"])
        assert clara["status"] == "FAIL"