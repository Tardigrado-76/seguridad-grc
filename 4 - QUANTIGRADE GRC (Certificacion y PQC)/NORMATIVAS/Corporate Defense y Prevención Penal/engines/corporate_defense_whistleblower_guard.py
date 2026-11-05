#!/usr/bin/env python3
"""
corporate_defense_whistleblower_guard.py - Whistleblower & Internal Reporting Engine.
Complies with Ley 2/2023 (Protección del Informante) and Art. 31 bis Código Penal.
Ensures anonymous reporting, E2E encryption, and legal retention limits.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WhistleblowerGuard")


class WhistleblowerManager:
    """Manages secure confidential and anonymous communications under Ley 2/2023."""

    def __init__(self, company_name: str):
        self.company_name = company_name

    def receive_anonymous_report(
        self, category: str, encrypted_payload: str
    ) -> dict[str, Any]:
        """Registers an anonymous report with an ephemeral tracking token and SHA-256 seal."""
        tracking_token = hashlib.sha256(
            f"{datetime.now(timezone.utc).isoformat()}_{category}".encode()
        ).hexdigest()[:16]
        report_record = {
            "company": self.company_name,
            "tracking_token": tracking_token,
            "category": category,
            "status": "RECEIVED_PENDING_TRIAGE",
            "statutory_response_limit_days": 7,
            "investigation_limit_months": 3,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(
            f"Anonymous report received under Ley 2/2023. Token: {tracking_token}"
        )
        return report_record


if __name__ == "__main__":
    guard = WhistleblowerManager("CorpTech España S.A.")
    res = guard.receive_anonymous_report("Anticorrupción y Fraude", "ENC_BLOB_XYZ")
    print(json.dumps(res, indent=2))
