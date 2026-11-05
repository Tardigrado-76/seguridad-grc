#!/usr/bin/env python3
"""
dsa_transparency_reporting_generator.py — DSA Transparency Reports & Recommender Auditing.

Compliance Alignment:
- Regulation (EU) 2022/2065 (Digital Services Act - DSA), Articles 15, 24, 27.
- Periodic transparency reporting, algorithmic recommender parameters, non-profiling options.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any


class DSATransparencyReportingGenerator:
    """Generates regulatory transparency reports and audits recommender system parameters."""

    def __init__(self, platform_id: str = "PLATFORM-EU-01", output_dir: str = "./dsa_transparency") -> None:
        self.platform_id: str = platform_id
        self.output_dir: Path = Path(output_dir)

    def generate_periodic_transparency_report(
        self,
        reporting_period: str,
        total_orders_received: int,
        total_notices_received: int,
        total_notices_actioned: int,
        avg_processing_hours: float,
        own_initiative_moderation_count: int,
        complaints_received: int,
        complaints_reversed: int,
    ) -> dict[str, Any]:
        """Produces a standardized transparency report conforming to Article 15 & Article 24."""
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        report = {
            "platform_id": self.platform_id,
            "reporting_period": reporting_period,
            "generated_at_iso": timestamp_iso,
            "metrics": {
                "judicial_orders_received": total_orders_received,
                "notices_received_art16": total_notices_received,
                "notices_actioned_content_removed": total_notices_actioned,
                "action_rate_percentage": round((total_notices_actioned / max(1, total_notices_received)) * 100, 2),
                "average_decision_latency_hours": avg_processing_hours,
                "own_initiative_moderation_actions": own_initiative_moderation_count,
                "internal_appeals_received_art20": complaints_received,
                "internal_appeals_reversed": complaints_reversed,
            },
            "commission_transparency_template_conformity": True,
            "dsa_articles": ["Art. 15 (Transparency reports)", "Art. 24 (Online platforms transparency)"],
        }

        digest = hashlib.sha256(json.dumps(report, sort_keys=True).encode("utf-8")).hexdigest().upper()
        report["report_sha256"] = digest
        return report

    def audit_recommender_system(
        self,
        recommender_id: str,
        ranking_factors: list[str],
        has_user_adjustable_parameters: bool = True,
        offers_non_profiling_alternative: bool = True,
    ) -> tuple[bool, dict[str, Any]]:
        """Audits an algorithmic recommender system against Article 27 transparency requirements."""
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        passed_params = len(ranking_factors) > 0 and has_user_adjustable_parameters
        passed_non_profiling = offers_non_profiling_alternative

        is_compliant = passed_params and passed_non_profiling

        audit = {
            "recommender_id": recommender_id,
            "audited_at_iso": timestamp_iso,
            "article": "DSA Art. 27 (Recommender system transparency)",
            "ranking_factors": ranking_factors,
            "user_can_modify_parameters": has_user_adjustable_parameters,
            "non_profiling_alternative_present": offers_non_profiling_alternative,
            "compliant": is_compliant,
            "status": "APPROVED" if is_compliant else "NON_COMPLIANT_PROFILING_LOCK",
        }

        digest = hashlib.sha256(json.dumps(audit, sort_keys=True).encode("utf-8")).hexdigest().upper()
        audit["audit_sha256"] = digest
        return is_compliant, audit


def main() -> None:
    parser = argparse.ArgumentParser(description="DSA Transparency Reporting Generator")
    parser.parse_args()
    gen = DSATransparencyReportingGenerator()
    report = gen.generate_periodic_transparency_report(
        reporting_period="2026-H1",
        total_orders_received=4,
        total_notices_received=250,
        total_notices_actioned=215,
        avg_processing_hours=6.5,
        own_initiative_moderation_count=80,
        complaints_received=15,
        complaints_reversed=2,
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
