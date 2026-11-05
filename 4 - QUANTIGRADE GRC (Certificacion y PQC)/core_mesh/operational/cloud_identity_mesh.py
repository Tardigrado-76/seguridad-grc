"""Quantigrade GCR - Continuous Cloud & Identity Evidence Mesh.

Provides deterministic evaluators for public cloud security posture (AWS, Azure, GCP)
and enterprise Identity Provider (IdP) governance (Okta, Microsoft Entra ID, Google Workspace).
All assessments operate strictly without Docker or external runtime agents.
"""

from typing import Dict, Any, List, Optional

class CloudIdentityMesh:
    """Continuous evaluation mesh for multi-cloud infrastructure and identity governance."""

    @staticmethod
    def evaluate_aws_posture(config: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates AWS configuration against security baseline controls."""
        checks_passed: List[str] = []
        checks_failed: List[str] = []
        remediations: List[str] = []
        score = 0.0

        # 1. S3 Block Public Access
        s3_bpa = config.get("s3_block_public_access", False)
        if isinstance(s3_bpa, dict):
            is_bpa_full = (
                s3_bpa.get("BlockPublicAcls", False) and
                s3_bpa.get("IgnorePublicAcls", False) and
                s3_bpa.get("BlockPublicPolicy", False) and
                s3_bpa.get("RestrictPublicBuckets", False)
            )
        else:
            is_bpa_full = bool(s3_bpa)

        if is_bpa_full:
            score += 25.0
            checks_passed.append("S3 Block Public Access is globally enforced")
        else:
            checks_failed.append("S3 Public Access is not fully blocked")
            remediations.append("Enable S3 Account-level Block Public Access across all 4 parameters.")

        # 2. IAM Root Account MFA
        root_mfa = bool(config.get("iam_root_mfa_enabled", False))
        if root_mfa:
            score += 25.0
            checks_passed.append("IAM root account has hardware or virtual MFA enabled")
        else:
            checks_failed.append("IAM root account lacks MFA")
            remediations.append("Enforce hardware FIDO2 MFA for AWS root account immediately.")

        # 3. CloudTrail Multi-Region
        cloudtrail_mr = bool(config.get("cloudtrail_multiregion_enabled", False))
        if cloudtrail_mr:
            score += 25.0
            checks_passed.append("CloudTrail multi-region audit trail is active and logging")
        else:
            checks_failed.append("CloudTrail multi-region is disabled")
            remediations.append("Enable global multi-region CloudTrail with KMS key encryption and log file validation.")

        # 4. Security Hub Findings
        crit_findings = int(config.get("security_hub_critical_findings", 0))
        if crit_findings == 0:
            score += 25.0
            checks_passed.append("Zero critical findings in AWS Security Hub")
        else:
            penalty = min(25.0, crit_findings * 5.0)
            awarded = max(0.0, 25.0 - penalty)
            score += awarded
            checks_failed.append(f"{crit_findings} unresolved critical finding(s) in AWS Security Hub")
            remediations.append(f"Triage and remediate {crit_findings} critical findings in Security Hub.")

        score = round(score, 1)
        status = "GREEN" if score >= 80.0 else ("AMBER" if score >= 50.0 else "RED")
        return {
            "provider": "AWS",
            "score_percentage": score,
            "status": status,
            "checks_passed": checks_passed,
            "checks_failed": checks_failed,
            "remediations": remediations
        }

    @staticmethod
    def evaluate_azure_posture(config: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates Azure configuration against security baseline controls."""
        checks_passed: List[str] = []
        checks_failed: List[str] = []
        remediations: List[str] = []
        score = 0.0

        # 1. Azure Policy Compliance Rate (weight: 35)
        policy_rate = float(config.get("policy_compliance_percentage", 0.0))
        if policy_rate >= 90.0:
            score += 35.0
            checks_passed.append(f"Azure Policy compliance is optimal ({policy_rate}%)")
        elif policy_rate >= 70.0:
            awarded = round(35.0 * (policy_rate / 100.0), 1)
            score += awarded
            checks_passed.append(f"Azure Policy compliance is moderate ({policy_rate}%)")
        else:
            checks_failed.append(f"Azure Policy compliance is deficient ({policy_rate}%)")
            remediations.append("Remediate non-compliant Azure Policy definitions for resource tagging and network security.")

        # 2. Defender for Cloud Secure Score (weight: 35)
        defender_score = float(config.get("defender_secure_score_percentage", 0.0))
        if defender_score >= 80.0:
            score += 35.0
            checks_passed.append(f"Microsoft Defender for Cloud secure score is strong ({defender_score}%)")
        elif defender_score >= 50.0:
            awarded = round(35.0 * (defender_score / 100.0), 1)
            score += awarded
            checks_passed.append(f"Defender secure score is moderate ({defender_score}%)")
        else:
            checks_failed.append(f"Defender secure score is low ({defender_score}%)")
            remediations.append("Implement Microsoft Defender for Cloud security recommendations.")

        # 3. Key Vault Purge Protection (weight: 30)
        purge_prot = bool(config.get("key_vault_purge_protection_enabled", False))
        if purge_prot:
            score += 30.0
            checks_passed.append("Key Vault purge protection and soft-delete are enforced")
        else:
            checks_failed.append("Key Vault purge protection is not enabled")
            remediations.append("Enable purge protection on all Azure Key Vaults to prevent crypto ransomware.")

        score = round(score, 1)
        status = "GREEN" if score >= 80.0 else ("AMBER" if score >= 50.0 else "RED")
        return {
            "provider": "Azure",
            "score_percentage": score,
            "status": status,
            "checks_passed": checks_passed,
            "checks_failed": checks_failed,
            "remediations": remediations
        }

    @staticmethod
    def evaluate_gcp_posture(config: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates Google Cloud Platform configuration against security baseline controls."""
        checks_passed: List[str] = []
        checks_failed: List[str] = []
        remediations: List[str] = []
        score = 0.0

        # 1. Uniform Bucket-Level Access (weight: 35)
        ubla = bool(config.get("uniform_bucket_level_access_enforced", False))
        if ubla:
            score += 35.0
            checks_passed.append("Cloud Storage Uniform Bucket-Level Access (UBLA) is enforced")
        else:
            checks_failed.append("UBLA is disabled; object-level ACLs introduce exposure risks")
            remediations.append("Enforce Uniform Bucket-Level Access across all GCS buckets.")

        # 2. Security Command Center (SCC) Alerts (weight: 35)
        scc_crit = int(config.get("scc_critical_alerts_count", 0))
        if scc_crit == 0:
            score += 35.0
            checks_passed.append("Zero critical alerts in Google Cloud Security Command Center")
        else:
            penalty = min(35.0, scc_crit * 7.0)
            score += max(0.0, 35.0 - penalty)
            checks_failed.append(f"{scc_crit} active critical findings in SCC")
            remediations.append(f"Resolve {scc_crit} critical threat alerts in Google Cloud SCC.")

        # 3. VPC Service Controls (weight: 30)
        vpc_sc = bool(config.get("vpc_service_controls_active", False))
        if vpc_sc:
            score += 30.0
            checks_passed.append("VPC Service Controls service perimeters are active")
        else:
            checks_failed.append("VPC Service Controls are not active")
            remediations.append("Establish VPC Service Controls perimeters for sensitive APIs.")

        score = round(score, 1)
        status = "GREEN" if score >= 80.0 else ("AMBER" if score >= 50.0 else "RED")
        return {
            "provider": "GCP",
            "score_percentage": score,
            "status": status,
            "checks_passed": checks_passed,
            "checks_failed": checks_failed,
            "remediations": remediations
        }

    @staticmethod
    def evaluate_identity_governance(idp_users: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Audits enterprise identity governance across Okta, Microsoft Entra ID, or Google Workspace."""
        total_accounts = len(idp_users)
        if total_accounts == 0:
            return {
                "score_percentage": 0.0,
                "status": "RED",
                "total_accounts": 0,
                "mfa_adoption_rate": 0.0,
                "inactive_accounts": [],
                "orphaned_service_accounts": [],
                "stale_credentials": [],
                "violations_count": 0,
                "remediations": ["No user accounts detected in IdP payload. Connect IdP directory."]
            }

        mfa_enabled_count = 0
        inactive_accounts: List[Dict[str, Any]] = []
        orphaned_service_accounts: List[Dict[str, Any]] = []
        stale_credentials: List[Dict[str, Any]] = []

        for user in idp_users:
            uname = user.get("username", "unknown")
            is_svc = bool(user.get("is_service_account", False))
            
            # MFA check
            if user.get("mfa_enabled", False):
                mfa_enabled_count += 1

            # Inactivity check (>90 days without login)
            last_login = user.get("last_login_days", 0)
            if last_login > 90 and not is_svc:
                inactive_accounts.append({
                    "username": uname,
                    "last_login_days": last_login,
                    "status": "DORMANT_OVER_90D"
                })

            # Orphaned service account check (service account with no human owner)
            if is_svc:
                owner = user.get("owner")
                if not owner or str(owner).strip().lower() in ["none", "null", ""]:
                    orphaned_service_accounts.append({
                        "username": uname,
                        "issue": "MISSING_HUMAN_OWNER"
                    })

            # Stale credential check (>90 days old)
            key_age = user.get("api_key_age_days")
            if key_age is not None and key_age > 90:
                stale_credentials.append({
                    "username": uname,
                    "key_age_days": key_age,
                    "issue": "KEY_EXCEEDS_90D_ROTATION_SLA"
                })

        mfa_rate = round((mfa_enabled_count / total_accounts) * 100.0, 1)

        # Scoring logic
        # MFA adoption: up to 50 pts
        score = (mfa_rate / 100.0) * 50.0

        # Inactive accounts deduction (up to 20 pts)
        inactive_ratio = len(inactive_accounts) / total_accounts
        score += max(0.0, 20.0 * (1.0 - (inactive_ratio * 3.0)))

        # Orphaned service accounts deduction (up to 15 pts)
        orphaned_ratio = len(orphaned_service_accounts) / max(1, total_accounts)
        score += max(0.0, 15.0 * (1.0 - (orphaned_ratio * 4.0)))

        # Stale credentials deduction (up to 15 pts)
        stale_ratio = len(stale_credentials) / max(1, total_accounts)
        score += max(0.0, 15.0 * (1.0 - (stale_ratio * 4.0)))

        score = round(min(100.0, max(0.0, score)), 1)
        status = "GREEN" if score >= 80.0 else ("AMBER" if score >= 50.0 else "RED")

        remediations = []
        if mfa_rate < 100.0:
            remediations.append(f"Enforce mandatory phishing-resistant MFA for all users (currently at {mfa_rate}%).")
        if inactive_accounts:
            remediations.append(f"Deprovision or suspend {len(inactive_accounts)} accounts dormant for >90 days.")
        if orphaned_service_accounts:
            remediations.append(f"Assign designated human owners to {len(orphaned_service_accounts)} orphaned service accounts.")
        if stale_credentials:
            remediations.append(f"Rotate {len(stale_credentials)} API credentials exceeding the 90-day rotation threshold.")

        return {
            "score_percentage": score,
            "status": status,
            "total_accounts": total_accounts,
            "mfa_adoption_rate": mfa_rate,
            "inactive_accounts": inactive_accounts,
            "orphaned_service_accounts": orphaned_service_accounts,
            "stale_credentials": stale_credentials,
            "violations_count": len(inactive_accounts) + len(orphaned_service_accounts) + len(stale_credentials),
            "remediations": remediations
        }
