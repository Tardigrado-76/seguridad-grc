import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core_mesh.business_execution.trust_center_engine import TrustCenterEngine
from core_mesh.business_execution.merkle_bunker import MerkleBunker, EvidenceSeal

class TestTrustCenterEngine(unittest.TestCase):
    def setUp(self):
        self.bunker = MerkleBunker(secret_key="unit-test-secret-key-32-bytes!!")
        self.engine = TrustCenterEngine(
            company_name="Acme Corp Enterprise",
            domain="acme.eu",
            dpo_email="dpo@acme.eu",
            merkle_bunker=self.bunker
        )

    def test_register_subprocessors_jurisdiction(self):
        # 1. EEA subprocessor
        sp_eea = self.engine.register_subprocessor(
            name="Hetzner Online GmbH",
            purpose="Primary Cloud Hosting",
            location="Germany (EEA)"
        )
        self.assertTrue(sp_eea["is_eea"])
        self.assertEqual(sp_eea["risk_level"], "LOW")
        self.assertIn("Adequate", sp_eea["transfer_status"])

        # 2. Non-EEA compliant subprocessor (US with DPF/SCCs)
        sp_us_ok = self.engine.register_subprocessor(
            name="AWS US-East",
            purpose="Disaster Recovery Backup",
            location="United States",
            transfer_mechanism="Standard Contractual Clauses (SCCs)",
            is_schrems_compliant=True
        )
        self.assertFalse(sp_us_ok["is_eea"])
        self.assertEqual(sp_us_ok["risk_level"], "MEDIUM")
        self.assertIn("Compliant", sp_us_ok["transfer_status"])

        # 3. Non-EEA non-compliant subprocessor
        sp_bad = self.engine.register_subprocessor(
            name="Shadow Analytics Inc",
            purpose="Unvetted telemetry",
            location="Offshore",
            is_schrems_compliant=False
        )
        self.assertFalse(sp_bad["is_eea"])
        self.assertEqual(sp_bad["risk_level"], "HIGH")
        self.assertIn("Non-Compliant", sp_bad["transfer_status"])

    def test_generate_trust_profile_and_cryptographic_seal(self):
        compliance_data = {
            "ISO 27001 - SOC2": {"score_percentage": 92.5, "status": "GREEN"},
            "RGPD - LOPDGDD": {"score_percentage": 85.0, "status": "GREEN"},
            "NIS2": {"score_percentage": 65.0, "status": "AMBER"},
            "Mandato PQC NIST FIPS 203-204": {"score_percentage": 100.0, "status": "GREEN"}
        }
        profile = self.engine.generate_trust_profile(compliance_data)

        self.assertEqual(profile["company_name"], "Acme Corp Enterprise")
        self.assertEqual(profile["domain"], "acme.eu")
        self.assertAlmostEqual(profile["average_compliance_score"], 85.6, places=1)
        self.assertEqual(profile["overall_status"], "GREEN")

        # Verify badges
        badges = profile["framework_badges"]
        self.assertEqual(badges["NIS2"]["status"], "AMBER")
        self.assertEqual(badges["NIS2"]["badge_label"], "Partial")
        self.assertEqual(badges["Mandato PQC NIST FIPS 203-204"]["status"], "GREEN")

        # Verify cryptographic seal
        seal_info = profile["cryptographic_seal"]
        self.assertTrue(seal_info["verification_ready"])
        self.assertIsNotNone(seal_info["merkle_root"])
        self.assertIsNotNone(seal_info["pqc_ml_dsa_signature"])

    def test_export_signed_evidence_package(self):
        compliance_data = {"DORA": 88.0, "ENS": 74.0}
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "signed_evidence.json")
            pkg = self.engine.export_signed_evidence_package(compliance_data, output_path=out_file)
            
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["schema_version"], "1.0-PQC")
            self.assertIn("trust_profile", loaded)

    def test_render_html_trust_portal(self):
        self.engine.register_subprocessor("ScaleWay", "Compute Nodes", "France (UE)")
        profile = self.engine.generate_trust_profile({"CRA": 95.0, "EU AI Act": 40.0})
        html_page = self.engine.render_html_trust_portal(profile)

        self.assertIn("<!DOCTYPE html>", html_page)
        self.assertIn("Acme Corp Enterprise Trust Center", html_page)
        self.assertIn("CRA", html_page)
        self.assertIn("ScaleWay", html_page)
        self.assertIn("Sellado Criptográfico Merkle Bunker Dual", html_page)

if __name__ == "__main__":
    unittest.main()
