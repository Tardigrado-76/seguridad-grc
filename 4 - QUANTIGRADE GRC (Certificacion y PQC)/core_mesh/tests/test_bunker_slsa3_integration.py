"""Unit and integration tests for Evidence Bunker SLSA3 components integrated into Quantigrade GCR.
Zero-Docker Native Python Verification Suite.
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

# Ensure QUANTIGRADE GCR root is in sys.path
_qg_root = str(Path(__file__).resolve().parents[2])
if _qg_root not in sys.path:
    sys.path.insert(0, _qg_root)

import pytest

from core_mesh.operational.slsa_provenance_engine import SLSAProvenanceEngine
from core_mesh.operational.zkp_auth_gateway import ZeroKnowledgeProofAuthGateway
from core_mesh.operational.immutable_log_verifier import ImmutableLogVerifier
from core_mesh.operational.encrypted_evidence_vault import EncryptedEvidenceVault
from core_mesh.operational.mtls_mesh_factory import MTLSMeshFactory
from core_mesh.remediation.auto_remediator import AutoRemediator
from NORMATIVAS.DORA.cloud_exit_strategy_tester import DORACloudExitTester
from NORMATIVAS.DORA.dora_chaos_resilience_tester import DORAChaosTester
from console.backend.config.clients import CLIENTS_REGISTRY, SCRIPTS_REGISTRY, resolve_script_path


class TestSLSAProvenanceEngine:
    def test_generate_and_verify_provenance(self, tmp_path):
        engine = SLSAProvenanceEngine()
        artifact_file = tmp_path / "production_binary.exe"
        artifact_file.write_bytes(b"SYNTHETIC_COMPILED_BINARY_PAYLOAD_V3")

        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}), encoding="utf-8")

        prov_statement = engine.generate_provenance(
            artifact_path=artifact_file,
            sbom_path=sbom_file,
        )
        assert prov_statement["_type"] == "https://in-toto.io/Statement/v1"
        assert prov_statement["predicateType"] == "https://slsa.dev/provenance/v1.0"
        assert len(prov_statement["subject"]) == 1

        prov_path = tmp_path / "provenance.slsa.json"
        engine.save_provenance(prov_statement, prov_path)
        assert prov_path.exists()

        is_valid, errors = engine.verify_provenance(
            artifact_path=artifact_file,
            provenance_path=prov_path,
            expected_sbom_path=sbom_file,
        )
        assert is_valid is True
        assert len(errors) == 0

    def test_verify_tampered_artifact_fails(self, tmp_path):
        engine = SLSAProvenanceEngine()
        artifact_file = tmp_path / "app.exe"
        artifact_file.write_bytes(b"ORIGINAL_BYTES")

        prov_statement = engine.generate_provenance(artifact_path=artifact_file)
        prov_path = tmp_path / "app.slsa.json"
        engine.save_provenance(prov_statement, prov_path)

        # Mutate artifact bytes (simulate supply chain tampering)
        artifact_file.write_bytes(b"MALICIOUS_TAMPERED_BYTES")

        is_valid, errors = engine.verify_provenance(
            artifact_path=artifact_file,
            provenance_path=prov_path,
        )
        assert is_valid is False
        assert any("does not match provenance" in e for e in errors)


class TestZKPAuthGateway:
    def test_zkp_handshake_success(self):
        gateway = ZeroKnowledgeProofAuthGateway(dry_run=True)
        prover_id = "node-microservice-01"
        secret = "SECRET_PASSWORD_VIP_NODE"

        proof = gateway.generate_zkp_proof(prover_id, secret)
        assert "public_commitment_y" in proof
        assert "challenge_c" in proof
        assert "response_s" in proof

        is_valid, reason = gateway.verify_zkp_proof(proof)
        assert is_valid is True
        assert reason == "ZKP_AUTHENTICATION_SUCCESSFUL"

    def test_zkp_invalid_secret_fails(self):
        gateway = ZeroKnowledgeProofAuthGateway(dry_run=True)
        proof = gateway.generate_zkp_proof("attacker_node", "VALID_SECRET")
        # Tamper response s
        proof["response_s"] = hex(int(proof["response_s"], 16) + 12345)

        is_valid, reason = gateway.verify_zkp_proof(proof)
        assert is_valid is False
        assert "INVALID_ZKP_PROOF" in reason

    def test_zkp_authenticate_node(self):
        gateway = ZeroKnowledgeProofAuthGateway(dry_run=True)
        session = gateway.authenticate_prover_node("auditor-bot", "STRONG_TOKEN_777")
        assert session["zkp_verified"] is True
        assert session["status"] == "AUTHENTICATED"


class TestImmutableLogVerifier:
    def test_create_and_verify_clean_log(self, tmp_path):
        log_file = tmp_path / "audit_chain.log"
        ImmutableLogVerifier.create_chained_log_file(log_file, num_entries=5)

        verifier = ImmutableLogVerifier(log_file)
        report = verifier.verify_integrity()
        assert report.total_lines_scanned == 5
        assert report.valid_lines_count == 5
        assert report.tampered_lines_count == 0
        assert report.is_integrity_intact is True
        assert len(report.merkle_root_hash) == 64
        assert report.dora_compliance_status == "CONFORME_DORA_ART10"

    def test_tampered_log_detected(self, tmp_path):
        log_file = tmp_path / "audit_chain.log"
        ImmutableLogVerifier.create_chained_log_file(log_file, num_entries=5)

        # Mutate line 3 content
        lines = log_file.read_text(encoding="utf-8").splitlines()
        parts = lines[2].split(" | ")
        lines[2] = f"{parts[0]} | TAMPERED_EVENT_UNAUTHORIZED | {parts[2]} | {parts[3]}"
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        verifier = ImmutableLogVerifier(log_file)
        report = verifier.verify_integrity()
        assert report.is_integrity_intact is False
        assert report.tampered_lines_count > 0
        assert report.chain_broken_at_line == 3
        assert report.dora_compliance_status == "NO_CONFORME_MODIFICACION_DETECTADA"


class TestCloudExitStrategyTester:
    def test_exit_strategy_dry_run(self, tmp_path):
        tester = DORACloudExitTester(
            provider_name="Test Cloud Critical",
            target_infra="Sovereign Vault Staging",
            db_size_gb=2.0,
            sla_rto_hours=1.0,
            sla_rpo_hours=0.5,
        )
        report = tester.run_dry_run(work_dir=tmp_path)
        assert report.provider_name == "Test Cloud Critical"
        assert report.overall_exit_success is True
        assert report.dora_compliance_verdict == "EXIT_STRATEGY_VALIDATED"
        assert report.actual_rto_minutes > 0.0
        assert report.actual_rpo_minutes >= 0.0


class TestDORAChaosTester:
    def test_chaos_dry_run_pipeline(self, tmp_path):
        tester = DORAChaosTester(scenario="network_drop", dry_run=True, output_dir=str(tmp_path))
        result = tester.run_full_test()
        assert result["recovered"] is True
        assert result["panic_triggered"] is False
        assert Path(result["json_report"]).exists()
        assert Path(result["md_report"]).exists()
        assert len(result["sha256"]) == 64


class TestEncryptedEvidenceVault:
    def test_backup_and_restore_sqlite(self, tmp_path):
        vault = EncryptedEvidenceVault(master_key="TEST_INTEGRATION_KEY_123")
        db_file = tmp_path / "audit_evidence.db"

        # Create original DB
        conn = sqlite3.connect(str(db_file))
        cur = conn.cursor()
        cur.execute("CREATE TABLE evidence (id INT, seal_hash TEXT);")
        cur.execute("INSERT INTO evidence VALUES (1, 'HASH_PROOF_ABC_999');")
        conn.commit()
        conn.close()

        # Execute backup
        backup_dir = tmp_path / "backups"
        enc_file = vault.backup_database(db_file, backup_dir=backup_dir)
        assert enc_file.exists()
        assert enc_file.suffix == ".enc"

        # Restore into separate dir
        restore_dir = tmp_path / "restored"
        restored_db = vault.restore_database(enc_file, target_dir=restore_dir)
        assert restored_db.exists()

        # Check restored data
        conn_res = sqlite3.connect(str(restored_db))
        cur_res = conn_res.cursor()
        cur_res.execute("SELECT seal_hash FROM evidence WHERE id=1;")
        val = cur_res.fetchone()[0]
        conn_res.close()
        assert val == "HASH_PROOF_ABC_999"


class TestMTLSMeshFactory:
    def test_mtls_factory_mesh_generation(self, tmp_path):
        factory = MTLSMeshFactory(certs_dir=tmp_path)
        res = factory.build_complete_mesh_pki()
        assert Path(res["ca_cert"]).exists()
        assert Path(res["ca_key"]).exists()
        assert Path(res["server_cert"]).exists()
        assert Path(res["server_key"]).exists()
        assert Path(res["client_cert"]).exists()
        assert Path(res["client_key"]).exists()

        is_expiring = factory.check_cert_expiry(res["ca_cert"], threshold_days=10)
        assert is_expiring is False


class TestAutoRemediatorBunkerHandlers:
    def test_remediator_bunker_handlers(self, tmp_path):
        remediator = AutoRemediator()
        assert "AIRGAP_ISOLATE" in remediator.handlers
        assert "ENCRYPTED_VAULT_BACKUP" in remediator.handlers

        airgap_res = remediator.execute_remediation("AIRGAP_ISOLATE", {"dry_run": True, "attacker_ip": "10.0.0.99"})
        assert airgap_res["status"] == "SUCCESS"
        assert airgap_res["action"] == "AIRGAP_ISOLATION_APPLIED"

        db_path = tmp_path / "dummy.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE t (id INT);")
        conn.commit()
        conn.close()

        vault_res = remediator.execute_remediation(
            "ENCRYPTED_VAULT_BACKUP",
            {"db_path": str(db_path), "backup_dir": str(tmp_path / "vault")},
        )
        assert vault_res["status"] == "SUCCESS"
        assert vault_res["action"] == "ENCRYPTED_VAULT_BACKUP_CREATED"


class TestConsoleBunkerScriptsRegistry:
    def test_console_bunker_scripts(self):
        bunker_scripts = [
            "slsa_provenance",
            "zkp_auth",
            "log_immutability",
            "encrypted_vault",
            "mtls_mesh",
            "cloud_exit_test",
            "dora_chaos_test",
        ]
        for s in bunker_scripts:
            assert s in SCRIPTS_REGISTRY, f"Script {s} must be registered in SCRIPTS_REGISTRY"
            script_path = resolve_script_path("default_tenant", s)
            assert script_path.exists(), f"Physical script for {s} does not exist at {script_path}"

