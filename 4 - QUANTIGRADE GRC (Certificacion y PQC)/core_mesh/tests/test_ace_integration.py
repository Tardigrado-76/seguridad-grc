"""Unit and integration tests for ACE components integrated into Quantigrade GCR.
Zero-Docker Native Python Verification Suite.
"""

import json
import os
import sys
import tempfile
import sqlite3
from pathlib import Path

# Ensure QUANTIGRADE GCR root is in sys.path
_qg_root = str(Path(__file__).resolve().parents[2])
if _qg_root not in sys.path:
    sys.path.insert(0, _qg_root)

import pytest

from core_mesh.operational.ast_scanner import ASTScanner
from core_mesh.operational.supply_chain_auditor import SupplyChainAuditor
from core_mesh.operational.rng_entropy_monitor import RNGEntropyMonitor
from core_mesh.operational.fips_mode_enforcer import FIPSModeEnforcer
from core_mesh.operational.iac_drift_auditor import ENISACloudIaCDriftAuditor
from core_mesh.operational.nis2_mfa_auditor import NIS2MFASecureCommsAuditor
from core_mesh.operational.fips_zeroization_auditor import FIPS1403ZeroizationAuditor
from core_mesh.operational.sar_data_extractor import SARDataExtractor
from core_mesh.remediation.auto_remediator import AutoRemediator
from console.backend.config.clients import CLIENTS_REGISTRY, SCRIPTS_REGISTRY, resolve_script_path


class TestASTScanner:
    def test_scan_dependencies_and_guards(self, tmp_path):
        scanner = ASTScanner()
        test_file = tmp_path / "sample_app.py"
        test_file.write_text(
            "import os\n"
            "import yaml\n"
            "try:\n"
            "    x = 1\n"
            "except Exception:\n"
            "    pass\n",
            encoding="utf-8"
        )

        dep_res = scanner.scan_dependencies(test_file)
        assert "detected_packages" in dep_res
        assert "PyYAML" in dep_res["detected_packages"]

        guard_res = scanner.scan_exception_guards(test_file)
        assert guard_res["status"] == "SUCCESS"
        assert guard_res["files_scanned"] == 1
        assert "broad_exceptions_count" in guard_res


class TestSupplyChainAuditor:
    def test_supply_chain_vex_and_kev(self, tmp_path):
        auditor = SupplyChainAuditor(base_path=tmp_path)
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("reqeusts==2.25.1\nhttp://insecure-repo.org/pkg\n", encoding="utf-8")

        res = auditor.audit_manifest(req_file)
        assert len(res) == 2
        assert any(f["type"] == "TYPOSQUATTING_SUSPECT" for f in res)
        assert any(f["type"] == "UNENCRYPTED_REPOSITORY" for f in res)

        vex_data = [
            {"cve_id": "CVE-2024-0001", "status": "not_affected", "justification": "Component not present"},
            {"cve_id": "CVE-2024-0002", "status": "affected", "impact_statement": "Patch in progress"}
        ]
        aggregated = auditor.aggregate_vex(vex_data)
        assert aggregated["total_evaluated"] == 2
        assert aggregated["suppressed_false_positives"] == 1
        assert aggregated["actionable_vulnerabilities"] == 1


class TestRNGEntropyMonitor:
    def test_entropy_evaluation(self):
        monitor = RNGEntropyMonitor(sample_size_bytes=512)
        rep_passed, max_rep = monitor.repetition_count_test(b"A" * 10)
        assert rep_passed is True

        health = monitor.evaluate_entropy_health()
        assert "status" in health
        assert health["status"] in ["ENTROPY_HEALTHY", "ENTROPY_DEGRADED_SP800_90B"]
        assert "available_entropy_bits" in health


class TestFIPSModeEnforcer:
    def test_fips_audit(self):
        enforcer = FIPSModeEnforcer(dry_run=True)
        is_enabled, details = enforcer.check_kernel_fips_mode()
        assert isinstance(is_enabled, bool)
        assert isinstance(details, str)

        crypto_audit = enforcer.audit_crypto_providers()
        assert "openssl_version" in crypto_audit
        assert "fips_compliant_provider" in crypto_audit


class TestIaCDriftAuditor:
    def test_iac_drift_scan(self, tmp_path):
        auditor = ENISACloudIaCDriftAuditor(iac_dir=str(tmp_path), dry_run=True)
        drifts = auditor.audit_iac_manifests()
        assert isinstance(drifts, list)
        assert len(drifts) > 0
        assert any("ENISA-IAC" in d["rule_id"] for d in drifts)


class TestNIS2MFAAuditor:
    def test_mfa_auditor(self, tmp_path):
        auditor = NIS2MFASecureCommsAuditor()
        conf_file = tmp_path / "web.conf"
        conf_file.write_text("server {\n  mfa_required = true;\n  webauthn = enabled;\n}\n", encoding="utf-8")

        res = auditor.audit_config(tmp_path)
        assert res["files_scanned"] >= 1
        assert res["mfa_services_count"] >= 1
        assert len(res["mfa_details"]) >= 1


class TestFIPSZeroizationAuditor:
    def test_key_zeroization_audit(self, tmp_path):
        auditor = FIPS1403ZeroizationAuditor()
        code_file = tmp_path / "crypto.c"
        code_file.write_text(
            "void clear_keys() {\n  explicit_bzero(key, 32);\n  secure_memzero(salt, 16);\n}\n",
            encoding="utf-8"
        )
        res = auditor.audit_source_code(tmp_path)
        assert res["files_scanned"] >= 1
        assert res["zeroization_routines_count"] >= 2
        assert len(res["zeroization_details"]) >= 2


class TestSARDataExtractor:
    def test_sar_sqlite_extraction(self, tmp_path):
        db_file = tmp_path / "app.db"
        conn = sqlite3.connect(str(db_file))
        cur = conn.cursor()
        cur.execute("CREATE TABLE users (id INT, dni TEXT, email TEXT, phone TEXT);")
        cur.execute("INSERT INTO users VALUES (1, '12345678Z', 'test@test.es', '600112233');")
        cur.execute("INSERT INTO users VALUES (2, '87654321A', 'other@test.es', '600998877');")
        conn.commit()
        conn.close()

        extractor = SARDataExtractor(subject_identifier="12345678Z", target_db=str(db_file), dry_run=True)
        records = extractor.extract_from_sqlite(db_file)
        assert len(records) == 1
        assert records[0]["data"]["dni"] == "12345678Z"


class TestAutoRemediatorExtendedHandlers:
    def test_remediator_handlers(self):
        remediator = AutoRemediator()
        handlers = remediator.handlers.keys()
        expected = ["DISA_STIG", "ENS_FIM_SCAN", "LINUX_VPS", "KERNEL_HARDEN", "RGPD_PURGE", "SAR_EXTRACT"]
        for h in expected:
            assert h in handlers, f"Handler {h} must be registered in AutoRemediator"


class TestConsoleRegistry:
    def test_clients_and_scripts_registry(self):
        assert "default_tenant" in CLIENTS_REGISTRY
        assert "ast_scanner" in SCRIPTS_REGISTRY
        assert "dora_classifier" in SCRIPTS_REGISTRY

        script_path = resolve_script_path("default_tenant", "ast_scanner")
        assert script_path.exists()
        assert script_path.name == "ast_scanner.py"
