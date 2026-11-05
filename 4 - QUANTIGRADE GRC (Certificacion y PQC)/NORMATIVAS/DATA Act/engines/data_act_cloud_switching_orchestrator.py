#!/usr/bin/env python3
"""
data_act_cloud_switching_orchestrator.py — Cloud & Data Processing Service Switching Engine.

Compliance Alignment:
- Regulation (EU) 2023/2854 (Data Act), Chapter VI, Articles 23-29.
- Abolition of switching charges (Zero Egress Fees, Art. 29), Functional Equivalence (Art. 26).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import secrets
from pathlib import Path
from typing import Any, ClassVar


class DataActCloudSwitchingOrchestrator:
    """Coordinates cloud portability, egress fee audits, and switching assistance SLAs."""

    SUPPORTED_EXPORT_FORMATS: ClassVar[list[str]] = ["JSON", "PARQUET", "CSV", "SQL_DUMP", "CONTAINER_OCI"]
    MAX_MIGRATION_TRANSITION_DAYS: ClassVar[int] = 30

    def __init__(self, provider_id: str = "CLOUD-PROVIDER-EU-SOV", output_dir: str = "./cloud_switching") -> None:
        self.provider_id: str = provider_id
        self.output_dir: Path = Path(output_dir)
        self.migration_plans: dict[str, Any] = {}

    def plan_cloud_migration(
        self,
        customer_id: str,
        destination_provider: str,
        data_volume_gb: float,
        export_format: str = "PARQUET",
        egress_fee_eur: float = 0.0,
        transition_period_days: int = 30,
    ) -> dict[str, Any]:
        """Formulates an Article 23-29 compliant cloud switching migration plan."""
        plan_id = f"CSW-{secrets.token_hex(6).upper()}"
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        egress_valid, egress_msg = self.verify_zero_egress_fee(egress_fee_eur)
        format_valid, format_msg = self.verify_export_portability(export_format)
        sla_valid, sla_msg = self.audit_transition_sla(transition_period_days)

        plan = {
            "migration_id": plan_id,
            "created_at_iso": timestamp_iso,
            "customer_id": customer_id,
            "source_provider": self.provider_id,
            "destination_provider": destination_provider,
            "data_volume_gb": data_volume_gb,
            "export_format": export_format,
            "egress_fee_eur": egress_fee_eur,
            "transition_period_days": transition_period_days,
            "zero_egress_compliance": {
                "compliant": egress_valid,
                "detail": egress_msg,
            },
            "portability_compliance": {
                "compliant": format_valid,
                "detail": format_msg,
            },
            "sla_compliance": {
                "compliant": sla_valid,
                "detail": sla_msg,
            },
            "data_act_articles": [
                "Art. 23 (Removal of obstacles to switching)",
                "Art. 26 (Contractual terms & functional equivalence)",
                "Art. 29 (Abolition of switching charges)",
            ],
        }

        # Cryptographic anchor
        digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode("utf-8")).hexdigest().upper()
        plan["plan_sha256"] = digest

        self.migration_plans[plan_id] = plan
        return plan

    def verify_zero_egress_fee(self, egress_fee_eur: float) -> tuple[bool, str]:
        """Verifies Article 29 requirement: switching charges and data egress fees are eliminated (0.0 EUR)."""
        if egress_fee_eur > 0.0:
            return False, f"NON_COMPLIANT_EGRESS_FEE: Charging {egress_fee_eur} EUR violates Data Act Art. 29 zero egress mandate."
        return True, "ZERO_EGRESS_COMPLIANT: No switching fees or egress penalties imposed."

    def verify_export_portability(self, export_format: str) -> tuple[bool, str]:
        """Verifies Article 26(1) requirement for structured, widely used, machine-readable format."""
        if export_format.upper() not in self.SUPPORTED_EXPORT_FORMATS:
            return False, f"PROPRIETARY_LOCKIN: Format '{export_format}' not recognized as open European standard."
        return True, f"PORTABILITY_VERIFIED: Export format '{export_format}' satisfies open interoperability standard."

    def audit_transition_sla(self, transition_period_days: int) -> tuple[bool, str]:
        """Verifies Article 25/26 requirements for adequate transition assistance."""
        if transition_period_days < self.MAX_MIGRATION_TRANSITION_DAYS:
            return False, f"INSUFFICIENT_SLA: Minimum mandatory transition period is {self.MAX_MIGRATION_TRANSITION_DAYS} days."
        return True, "TRANSITION_SLA_COMPLIANT: Comprehensive switching assistance provided."


def main() -> None:
    parser = argparse.ArgumentParser(description="Data Act Cloud Switching Orchestrator")
    parser.parse_args()
    orchestrator = DataActCloudSwitchingOrchestrator()
    plan = orchestrator.plan_cloud_migration(
        customer_id="CORP-CLIENT-77",
        destination_provider="SOVEREIGN-EU-CLOUD-02",
        data_volume_gb=1250.0,
        export_format="PARQUET",
        egress_fee_eur=0.0,
        transition_period_days=30,
    )
    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
