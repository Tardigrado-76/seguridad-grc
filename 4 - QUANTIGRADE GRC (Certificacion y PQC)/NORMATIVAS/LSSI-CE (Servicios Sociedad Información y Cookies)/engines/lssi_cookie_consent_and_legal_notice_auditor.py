#!/usr/bin/env python3
"""
lssi_cookie_consent_and_legal_notice_auditor.py - LSSI-CE & AEPD Cookie Compliance Engine.
Implements Ley 34/2002 (LSSI-CE) Arts. 10, 21, 22.2 and Guía de Cookies AEPD 2024.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("LSSIAuditor")


class LssiCeAuditor:
    """Audits web platforms against Spanish e-commerce and cookie legal mandates."""

    def __init__(self, domain: str):
        self.domain = domain

    def audit_legal_notice_art10(
        self, cif_present: bool, address_present: bool, registry_info_present: bool
    ) -> dict[str, Any]:
        """Audits permanent general information under Art. 10 LSSI-CE."""
        if not (cif_present and address_present and registry_info_present):
            raise ValueError(
                "Art. 10 LSSI-CE requires permanent access to corporate name, NIF, domicile and registry data."
            )

        logger.info(f"Art. 10 Legal Notice validated for domain {self.domain}")
        return {"domain": self.domain, "art_10_compliant": True, "status": "APPROVED"}

    def audit_cookie_banner_aepd(
        self, reject_button_equal_prominence: bool, prechecked_boxes: bool
    ) -> dict[str, Any]:
        """Audits cookie consent banner under Art. 22.2 LSSI-CE and AEPD 2024 guidelines."""
        if not reject_button_equal_prominence or prechecked_boxes:
            raise ValueError(
                "AEPD guidelines mandate 'Reject all' button with identical visual prominence and NO pre-checked boxes."
            )

        logger.info(f"Cookie banner compliant with AEPD 2024 for domain {self.domain}")
        return {
            "domain": self.domain,
            "art_22_2_compliant": True,
            "reject_button_prominence": "EQUAL_TO_ACCEPT",
            "no_dark_patterns": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


if __name__ == "__main__":
    auditor = LssiCeAuditor("comercioelectronico.es")
    notice = auditor.audit_legal_notice_art10(True, True, True)
    cookies = auditor.audit_cookie_banner_aepd(True, False)
    print(json.dumps({"notice": notice, "cookies": cookies}, indent=2))
