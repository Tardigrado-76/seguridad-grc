import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core_mesh.operational.cloud_identity_mesh import CloudIdentityMesh

class TestCloudIdentityMesh(unittest.TestCase):
    def test_aws_posture_compliant(self):
        config = {
            "s3_block_public_access": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            },
            "iam_root_mfa_enabled": True,
            "cloudtrail_multiregion_enabled": True,
            "security_hub_critical_findings": 0
        }
        res = CloudIdentityMesh.evaluate_aws_posture(config)
        self.assertEqual(res["score_percentage"], 100.0)
        self.assertEqual(res["status"], "GREEN")
        self.assertEqual(len(res["checks_passed"]), 4)
        self.assertEqual(len(res["checks_failed"]), 0)

    def test_aws_posture_non_compliant(self):
        config = {
            "s3_block_public_access": False,
            "iam_root_mfa_enabled": False,
            "cloudtrail_multiregion_enabled": False,
            "security_hub_critical_findings": 3
        }
        res = CloudIdentityMesh.evaluate_aws_posture(config)
        self.assertLess(res["score_percentage"], 50.0)
        self.assertEqual(res["status"], "RED")
        self.assertEqual(len(res["checks_failed"]), 4)
        self.assertGreaterEqual(len(res["remediations"]), 4)

    def test_azure_posture(self):
        config_good = {
            "policy_compliance_percentage": 95.0,
            "defender_secure_score_percentage": 88.0,
            "key_vault_purge_protection_enabled": True
        }
        res_good = CloudIdentityMesh.evaluate_azure_posture(config_good)
        self.assertEqual(res_good["score_percentage"], 100.0)
        self.assertEqual(res_good["status"], "GREEN")

        config_bad = {
            "policy_compliance_percentage": 40.0,
            "defender_secure_score_percentage": 30.0,
            "key_vault_purge_protection_enabled": False
        }
        res_bad = CloudIdentityMesh.evaluate_azure_posture(config_bad)
        self.assertEqual(res_bad["score_percentage"], 0.0)
        self.assertEqual(res_bad["status"], "RED")

    def test_gcp_posture(self):
        config = {
            "uniform_bucket_level_access_enforced": True,
            "scc_critical_alerts_count": 0,
            "vpc_service_controls_active": True
        }
        res = CloudIdentityMesh.evaluate_gcp_posture(config)
        self.assertEqual(res["score_percentage"], 100.0)
        self.assertEqual(res["status"], "GREEN")

    def test_identity_governance(self):
        # Empty payload
        empty_res = CloudIdentityMesh.evaluate_identity_governance([])
        self.assertEqual(empty_res["score_percentage"], 0.0)
        self.assertEqual(empty_res["status"], "RED")

        # Mixed IdP directory with violations
        users = [
            {"username": "alice@corp.com", "mfa_enabled": True, "last_login_days": 1, "is_service_account": False},
            {"username": "bob@corp.com", "mfa_enabled": False, "last_login_days": 5, "is_service_account": False},
            {"username": "charlie@corp.com", "mfa_enabled": True, "last_login_days": 130, "is_service_account": False},  # Dormant
            {"username": "svc-backup", "mfa_enabled": True, "last_login_days": 2, "is_service_account": True, "owner": None}, # Orphaned
            {"username": "dev-api-key", "mfa_enabled": True, "last_login_days": 2, "is_service_account": False, "api_key_age_days": 150} # Stale key
        ]
        res = CloudIdentityMesh.evaluate_identity_governance(users)
        self.assertEqual(res["total_accounts"], 5)
        self.assertEqual(res["mfa_adoption_rate"], 80.0)
        self.assertEqual(len(res["inactive_accounts"]), 1)
        self.assertEqual(res["inactive_accounts"][0]["username"], "charlie@corp.com")
        self.assertEqual(len(res["orphaned_service_accounts"]), 1)
        self.assertEqual(res["orphaned_service_accounts"][0]["username"], "svc-backup")
        self.assertEqual(len(res["stale_credentials"]), 1)
        self.assertEqual(res["stale_credentials"][0]["username"], "dev-api-key")
        self.assertGreaterEqual(len(res["remediations"]), 4)

if __name__ == "__main__":
    unittest.main()
