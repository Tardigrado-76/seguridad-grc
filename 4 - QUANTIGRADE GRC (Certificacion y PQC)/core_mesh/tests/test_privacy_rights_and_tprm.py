import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core_mesh.remediation.privacy_rights_and_tprm import PrivacySARManager, VendorTPRMManager

class TestPrivacySARAndTPRM(unittest.TestCase):
    def test_sar_lifecycle_and_statutory_deadlines(self):
        sar = PrivacySARManager()
        
        # Valid request
        intake_t = 1000000.0
        req = sar.create_sar_request("SAR-001", "user@example.com", "Access", intake_timestamp=intake_t)
        self.assertEqual(req["request_type"], "Access")
        self.assertEqual(req["deadline_timestamp"], intake_t + (30 * 86400))
        self.assertFalse(req["extended_deadline"])

        # Invalid right type raises ValueError
        with self.assertRaises(ValueError):
            sar.create_sar_request("SAR-ERR", "user@example.com", "InvalidRight")

        # Urgency: at intake (30 days left) -> NORMAL
        st1 = sar.get_request_status("SAR-001", current_timestamp=intake_t)
        self.assertEqual(st1["urgency_level"], "NORMAL")
        self.assertEqual(st1["days_remaining"], 30.0)

        # Urgency: 20 days later (10 days left) -> ATTENTION
        st2 = sar.get_request_status("SAR-001", current_timestamp=intake_t + (20 * 86400))
        self.assertEqual(st2["urgency_level"], "ATTENTION")
        self.assertEqual(st2["days_remaining"], 10.0)

        # Urgency: 27 days later (3 days left) -> CRITICAL
        st3 = sar.get_request_status("SAR-001", current_timestamp=intake_t + (27 * 86400))
        self.assertEqual(st3["urgency_level"], "CRITICAL")
        self.assertEqual(st3["days_remaining"], 3.0)

        # Urgency: 31 days later (-1 day) -> BREACH_OVERDUE
        st4 = sar.get_request_status("SAR-001", current_timestamp=intake_t + (31 * 86400))
        self.assertEqual(st4["urgency_level"], "BREACH_OVERDUE")
        self.assertEqual(st4["days_remaining"], -1.0)

        # Legal Extension
        ext = sar.extend_request("SAR-001", "Extensive multi-system data archiving")
        self.assertTrue(ext["extended_deadline"])
        self.assertEqual(ext["deadline_timestamp"], intake_t + (90 * 86400))

        # Second extension must fail
        with self.assertRaises(ValueError):
            sar.extend_request("SAR-001", "Second extension not permitted by Art. 12.3")

        # Close request with proof hash
        closed = sar.close_sar_request("SAR-001", "Data package delivered via encrypted link", "delivery-hash-xyz")
        self.assertEqual(closed["status"], "COMPLETED")
        self.assertIsNotNone(closed["delivery_proof_hash"])

        st_closed = sar.get_request_status("SAR-001")
        self.assertEqual(st_closed["status"], "COMPLETED")
        self.assertEqual(st_closed["urgency_level"], "RESOLVED")

    def test_vendor_tprm_dora_and_schrems(self):
        tprm = VendorTPRMManager()

        # 1. Compliant Tier 1 Vendor (EU based, tested exit strategy, high score)
        v_eu = tprm.register_vendor(
            vendor_id="VND-001",
            vendor_name="OVHcloud SAS",
            service_description="Core Infrastructure",
            criticality_tier="TIER_1",
            data_hosted_in_eea=True,
            questionnaire_score=92.0,
            has_exit_strategy=True
        )
        self.assertEqual(v_eu["schrems_status"], "ADEQUATE_EEA")
        self.assertEqual(v_eu["schrems_risk"], "LOW")
        self.assertEqual(len(v_eu["dora_findings"]), 0)
        self.assertEqual(v_eu["overall_risk"], "LOW_RISK")

        # 2. Non-compliant Tier 1 Vendor (US based, missing exit strategy)
        v_us_bad = tprm.register_vendor(
            vendor_id="VND-002",
            vendor_name="Monolithic Cloud Inc",
            service_description="Core Database SaaS",
            criticality_tier="TIER_1",
            data_hosted_in_eea=False,
            questionnaire_score=60.0,
            has_exit_strategy=False,
            transfer_mechanism="None"
        )
        self.assertEqual(v_us_bad["schrems_status"], "SCHREMS_II_HIGH_RISK")
        self.assertEqual(v_us_bad["schrems_risk"], "HIGH")
        self.assertGreaterEqual(len(v_us_bad["dora_findings"]), 2)
        self.assertEqual(v_us_bad["overall_risk"], "HIGH_RISK")

        # 3. Safeguarded Non-EEA Vendor
        v_us_ok = tprm.register_vendor(
            vendor_id="VND-003",
            vendor_name="GitLab Inc",
            service_description="CI/CD Pipeline",
            criticality_tier="TIER_2",
            data_hosted_in_eea=False,
            questionnaire_score=85.0,
            has_exit_strategy=True,
            transfer_mechanism="Standard Contractual Clauses (SCCs)"
        )
        self.assertIn("SAFEGUARDED", v_us_ok["schrems_status"])
        self.assertEqual(v_us_ok["schrems_risk"], "MEDIUM")

        # Check summary
        summary = tprm.get_tprm_summary()
        self.assertEqual(summary["total_vendors"], 3)
        self.assertEqual(summary["critical_tier1_count"], 2)
        self.assertEqual(summary["significant_tier2_count"], 1)
        self.assertEqual(summary["schrems_high_risk_vendors"], 1)
        self.assertGreater(summary["dora_violations_count"], 0)

if __name__ == "__main__":
    unittest.main()
