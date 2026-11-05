#!/usr/bin/env python3
"""
dsa_illegal_content_moderation_engine.py — Illegal Content Moderation & Notice-and-Action Engine.

Compliance Alignment:
- Regulation (EU) 2022/2065 (Digital Services Act - DSA), Articles 16, 17, 20.
- Standardized Notice and Action, Statement of Reasons, and Internal Complaint-Handling.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import secrets
from pathlib import Path
from typing import Any, ClassVar


class DSAIllegalContentModerationEngine:
    """Orchestrates Notice & Action, Statement of Reasons, and Appeal processes under the DSA."""

    VALID_DECISION_TYPES: ClassVar[list[str]] = [
        "CONTENT_REMOVAL",
        "ACCESS_DISABLED",
        "DEMOTION_OR_DOWNRANKING",
        "ACCOUNT_SUSPENSION",
        "MONETISATION_RESTRICTION",
        "NO_ACTION_LEGAL",
    ]

    def __init__(self, platform_id: str = "PLATFORM-EU-01", output_dir: str = "./dsa_moderation") -> None:
        self.platform_id: str = platform_id
        self.output_dir: Path = Path(output_dir)
        self.notices: dict[str, Any] = {}
        self.statements_of_reasons: dict[str, Any] = {}
        self.appeals: dict[str, Any] = {}

    def submit_notice(
        self,
        notifier_email: str,
        content_id: str,
        legal_basis: str,
        explanation: str,
        exact_location_url: str,
    ) -> dict[str, Any]:
        """Processes an Article 16 Notice of alleged illegal content."""
        notice_id = f"DSA-NOT-{secrets.token_hex(6).upper()}"
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        notice = {
            "notice_id": notice_id,
            "timestamp_iso": timestamp_iso,
            "notifier_contact": hashlib.sha256(notifier_email.encode("utf-8")).hexdigest()[:16],
            "content_id": content_id,
            "legal_basis": legal_basis,
            "explanation": explanation,
            "exact_location_url": exact_location_url,
            "status": "UNDER_EXAMINATION",
            "dsa_art16_compliant": True,
        }

        digest = hashlib.sha256(json.dumps(notice, sort_keys=True).encode("utf-8")).hexdigest().upper()
        notice["notice_sha256"] = digest
        self.notices[notice_id] = notice
        return notice

    def issue_statement_of_reasons(
        self,
        notice_id: str,
        decision_type: str,
        legal_or_contractual_ground: str,
        facts_and_circumstances: str,
        automated_decision: bool = False,
    ) -> dict[str, Any]:
        """Generates an Article 17 Statement of Reasons suitable for the Commission's DSA Database."""
        if decision_type not in self.VALID_DECISION_TYPES:
            msg = f"Invalid decision type '{decision_type}'."
            raise ValueError(msg)

        sor_id = f"DSA-SOR-{secrets.token_hex(6).upper()}"
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        statement = {
            "statement_of_reasons_id": sor_id,
            "related_notice_id": notice_id,
            "issued_at_iso": timestamp_iso,
            "decision": decision_type,
            "ground": legal_or_contractual_ground,
            "facts": facts_and_circumstances,
            "automated_means_used": automated_decision,
            "redress_options": [
                "Internal complaint-handling system (Art. 20)",
                "Out-of-court dispute settlement (Art. 21)",
                "Judicial redress before national courts (Art. 53)",
            ],
            "commission_transparency_database_ready": True,
        }

        digest = hashlib.sha256(json.dumps(statement, sort_keys=True).encode("utf-8")).hexdigest().upper()
        statement["statement_sha256"] = digest
        self.statements_of_reasons[sor_id] = statement
        return statement

    def process_internal_complaint(
        self,
        statement_of_reasons_id: str,
        complainant_id: str,
        reasons_for_appeal: str,
    ) -> dict[str, Any]:
        """Processes an Article 20 internal appeal ensuring human, non-automated oversight."""
        appeal_id = f"DSA-APP-{secrets.token_hex(6).upper()}"
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        appeal = {
            "appeal_id": appeal_id,
            "statement_of_reasons_id": statement_of_reasons_id,
            "complainant_id": complainant_id,
            "reasons_for_appeal": reasons_for_appeal,
            "received_at_iso": timestamp_iso,
            "human_in_the_loop_mandatory": True,
            "status": "PENDING_QUALIFIED_HUMAN_REVIEW",
            "dsa_art20_compliant": True,
        }

        digest = hashlib.sha256(json.dumps(appeal, sort_keys=True).encode("utf-8")).hexdigest().upper()
        appeal["appeal_sha256"] = digest
        self.appeals[appeal_id] = appeal
        return appeal


def main() -> None:
    parser = argparse.ArgumentParser(description="DSA Illegal Content Moderation Engine")
    parser.parse_args()
    engine = DSAIllegalContentModerationEngine()
    notice = engine.submit_notice(
        notifier_email="trusted.flagger@ngo.eu",
        content_id="POST-881923",
        legal_basis="Hate speech / Incitement to violence (EU Framework Decision 2008/913/JHA)",
        explanation="Direct threats against protected groups.",
        exact_location_url="https://platform.eu/posts/881923",
    )
    sor = engine.issue_statement_of_reasons(
        notice_id=notice["notice_id"],
        decision_type="CONTENT_REMOVAL",
        legal_or_contractual_ground="DSA Art. 16 Notice validated against EU hate speech prohibition",
        facts_and_circumstances="Verified text content directly violated safety policy and criminal code",
        automated_decision=False,
    )
    print(json.dumps(sor, indent=2))


if __name__ == "__main__":
    main()
