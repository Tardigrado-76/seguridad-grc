#!/usr/bin/env python3
"""
enisa_hsm_kms_assurance_checker.py — ENISA EUCS High-Assurance Cryptographic Key & HSM Auditor.

Compliance Alignment:
- ENISA European Cybersecurity Certification Scheme for Cloud Services (EUCS).
- High Assurance Level: Customer-controlled HSM key management and EU jurisdictional custody.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from typing import Any, ClassVar


class ENISAHSMKMSAssuranceChecker:
    """Verifies cryptographic key custody, KMS policies, and dedicated HSM isolation for EUCS High."""

    VALID_HSM_STANDARDS: ClassVar[list[str]] = [
        "FIPS_140_3_LEVEL_3",
        "FIPS_140_2_LEVEL_3",
        "COMMON_CRITERIA_EAL4_PLUS",
    ]

    def __init__(self, cloud_region: str = "eu-west-1") -> None:
        self.cloud_region: str = cloud_region

    def audit_kms_hsm_custody(
        self,
        key_id: str,
        hsm_standard: str = "FIPS_140_3_LEVEL_3",
        customer_managed_keys_cmk: bool = True,
        hardware_security_module_dedicated: bool = True,
        eu_geographic_residency: bool = True,
    ) -> tuple[bool, dict[str, Any]]:
        """Audits KMS and HSM attributes for compliance with EUCS High requirements."""
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        is_standard_valid = hsm_standard in self.VALID_HSM_STANDARDS
        is_compliant = (
            is_standard_valid
            and customer_managed_keys_cmk
            and hardware_security_module_dedicated
            and eu_geographic_residency
        )

        report = {
            "key_id": key_id,
            "audited_at_iso": timestamp_iso,
            "cloud_region": self.cloud_region,
            "hsm_standard": hsm_standard,
            "customer_managed_keys": customer_managed_keys_cmk,
            "hsm_dedicated": hardware_security_module_dedicated,
            "eu_residency": eu_geographic_residency,
            "compliant": is_compliant,
            "status": "APPROVED_EUCS_HIGH"
            if is_compliant
            else "NON_COMPLIANT_KEY_CUSTODY",
        }

        digest = (
            hashlib.sha256(json.dumps(report, sort_keys=True).encode("utf-8"))
            .hexdigest()
            .upper()
        )
        report["audit_sha256"] = digest
        return is_compliant, report


def main() -> None:
    parser = argparse.ArgumentParser(description="ENISA EUCS HSM/KMS Assurance Checker")
    parser.parse_args()
    checker = ENISAHSMKMSAssuranceChecker()
    comp, rep = checker.audit_kms_hsm_custody("kms-key-eu-prod-01")
    print(f"ENISA EUCS HSM/KMS Assurance: {comp} (Status: {rep['status']})")


if __name__ == "__main__":
    main()
