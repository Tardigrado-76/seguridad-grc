#!/usr/bin/env python3
"""
lgtel_5g_network_security_auditor.py - Telecommunications Network Integrity & 5G Security Engine.
Implements Ley 11/2022 General de Telecomunicaciones (Arts. 110-118)
and Real Decreto-ley 7/2022 sobre seguridad de las redes y servicios 5G.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("LGTelAuditor")


class LGTelSecurityAuditor:
    """Audits telecommunications networks and 5G critical elements under Spanish law."""

    def __init__(self, operator_name: str):
        self.operator_name = operator_name

    def audit_5g_vendor_diversification(
        self, core_vendors: list[str], high_risk_vendors: list[str]
    ) -> dict[str, Any]:
        """Ensures compliance with RD-ley 7/2022 prohibiting high-risk vendors in 5G Core nodes."""
        infringing = [v for v in core_vendors if v in high_risk_vendors]
        if infringing:
            raise ValueError(f"High-risk vendor detected in 5G Core: {infringing}")

        logger.info(f"5G vendor diversification verified for {self.operator_name}")
        return {
            "operator": self.operator_name,
            "core_vendors": core_vendors,
            "high_risk_excluded": True,
            "status": "APPROVED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def verify_network_incident_procedure(self, notification_window_hours: int) -> bool:
        """Verifies that network disruptions are reported to the Ministry within legal limits."""
        if notification_window_hours > 24:
            return False
        logger.info("Incident notification procedure adheres to Art. 111 LGTel")
        return True


if __name__ == "__main__":
    auditor = LGTelSecurityAuditor("IberCom 5G Telecom")
    res = auditor.audit_5g_vendor_diversification(
        ["VendorEU-A", "VendorEU-B"], ["UntrustedVendorX"]
    )
    print(json.dumps(res, indent=2))
