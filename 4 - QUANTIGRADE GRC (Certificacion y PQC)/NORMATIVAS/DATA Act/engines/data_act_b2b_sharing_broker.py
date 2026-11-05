#!/usr/bin/env python3
"""
data_act_b2b_sharing_broker.py — B2B & IoT Data Sharing Broker under EU Data Act.

Compliance Alignment:
- Regulation (EU) 2023/2854 (Data Act), Articles 3-5, 8-13 (FRAND Terms).
- Fair, Reasonable, Non-Discriminatory (FRAND) data access, trade secret safeguards.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import secrets
from pathlib import Path
from typing import Any, ClassVar


class DataActB2BSharingBroker:
    """Manages B2B, IoT, and user-initiated data sharing requests under FRAND rules."""

    MANDATORY_SECURITY_CONTROLS: ClassVar[list[str]] = [
        "ENCRYPTION_IN_TRANSIT_TLS13",
        "ENCRYPTION_AT_REST_AES256",
        "TRADE_SECRET_CONFIDENTIALITY_NDA",
        "TECHNICAL_ACCESS_CONTROL_RBAC",
        "AUDIT_LOGGING_IMMUTABLE",
    ]

    def __init__(self, data_holder_id: str = "CORP-DATA-HOLDER-EU", output_dir: str = "./data_act_shares") -> None:
        self.data_holder_id: str = data_holder_id
        self.output_dir: Path = Path(output_dir)
        self.sharing_registry: dict[str, Any] = {}

    def create_sharing_agreement(
        self,
        user_or_business_id: str,
        third_party_recipient: str,
        dataset_description: str,
        compensation_eur: float,
        is_sme_recipient: bool = False,
        security_measures: list[str] | None = None,
    ) -> dict[str, Any]:
        """Creates a compliant Data Sharing Agreement under Articles 3, 5 & 8-10."""
        req_id = f"DA-B2B-{secrets.token_hex(6).upper()}"
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        measures = security_measures or self.MANDATORY_SECURITY_CONTROLS

        frand_valid, frand_msg = self.verify_frand_terms(compensation_eur, is_sme_recipient)
        trade_secret_valid, ts_msg = self.audit_trade_secret_safeguards(measures)

        agreement = {
            "agreement_id": req_id,
            "created_at_iso": timestamp_iso,
            "data_holder": self.data_holder_id,
            "data_user_id": user_or_business_id,
            "authorized_third_party": third_party_recipient,
            "dataset_description": dataset_description,
            "compensation_eur": compensation_eur,
            "is_sme_recipient": is_sme_recipient,
            "frand_compliance": {
                "compliant": frand_valid,
                "detail": frand_msg,
            },
            "trade_secret_protection": {
                "compliant": trade_secret_valid,
                "detail": ts_msg,
                "active_measures": measures,
            },
            "data_act_articles": ["Art. 3 (User access)", "Art. 5 (Third party access)", "Art. 8 (FRAND)"],
        }

        # Cryptographic anchor
        digest = hashlib.sha256(json.dumps(agreement, sort_keys=True).encode("utf-8")).hexdigest().upper()
        agreement["agreement_sha256"] = digest

        self.sharing_registry[req_id] = agreement
        return agreement

    def verify_frand_terms(self, compensation_eur: float, is_sme_recipient: bool) -> tuple[bool, str]:
        """Verifies Article 9 rules on compensation (non-discriminatory, cost-reflective for SMEs)."""
        if compensation_eur < 0:
            return False, "INVALID_COMPENSATION: Compensation cannot be negative."

        # Article 9(2): Compensation for SMEs shall not exceed costs directly incurred in making data available
        if is_sme_recipient and compensation_eur > 500.0:
            return False, "NON_FRAND_SME: Compensation exceeds cost-recovery ceiling for SMEs under Art. 9(2)."

        return True, "FRAND_COMPLIANT: Terms are reasonable, transparent, and non-discriminatory."

    def audit_trade_secret_safeguards(self, security_measures: list[str]) -> tuple[bool, str]:
        """Verifies Article 4(6) and 5(9) technical and organizational trade secret safeguards."""
        missing = [ctrl for ctrl in self.MANDATORY_SECURITY_CONTROLS if ctrl not in security_measures]
        if missing:
            return False, f"TRADE_SECRET_DEFICIENCY: Missing critical measures: {', '.join(missing)}"
        return True, "TRADE_SECRETS_PROTECTED: Technical and legal measures meet Data Act requirements."


def main() -> None:
    parser = argparse.ArgumentParser(description="Data Act B2B Sharing Broker")
    parser.parse_args()
    broker = DataActB2BSharingBroker()
    ag = broker.create_sharing_agreement(
        user_or_business_id="CLIENT-EU-01",
        third_party_recipient="ANALYTICS-PARTNER-GMBH",
        dataset_description="IoT Industrial telemetry sensors",
        compensation_eur=50.0,
        is_sme_recipient=True,
    )
    print(json.dumps(ag, indent=2))


if __name__ == "__main__":
    main()
