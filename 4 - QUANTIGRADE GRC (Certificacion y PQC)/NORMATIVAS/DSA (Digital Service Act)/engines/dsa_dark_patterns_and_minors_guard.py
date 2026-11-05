#!/usr/bin/env python3
"""
dsa_dark_patterns_and_minors_guard.py — Anti-Dark Patterns & Protection of Minors Engine.

Compliance Alignment:
- Regulation (EU) 2022/2065 (Digital Services Act - DSA), Articles 25, 28.
- Prohibition of deceptive design architectures, protection of minors, zero profiling ads for minors.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from typing import Any, ClassVar


class DSADarkPatternsAndMinorsGuard:
    """Audits user interface designs and minor safety policies against DSA Articles 25 and 28."""

    DARK_PATTERN_INDICATORS: ClassVar[list[str]] = [
        "ASYMMETRIC_CHOICE_CONFIRMSHAMING",
        "PRE_TICKED_CONSENT_BOX",
        "REPEATED_CONSENT_NUDGING_AFTER_REFUSAL",
        "HIDDEN_CANCELLATION_PROCESS",
        "FALSE_URGENCY_TIMER",
    ]

    def __init__(self) -> None:
        pass

    def audit_ui_interface_design(self, ui_components: list[dict[str, Any]]) -> tuple[bool, dict[str, Any]]:
        """Audits UI components against deceptive practices under Article 25."""
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        violations: list[str] = []

        for comp in ui_components:
            pattern = comp.get("pattern_detected")
            if pattern in self.DARK_PATTERN_INDICATORS:
                violations.append(f"Component '{comp.get('name', 'unknown')}': prohibited pattern '{pattern}'")

        is_clean = len(violations) == 0

        report = {
            "audited_at_iso": timestamp_iso,
            "article": "DSA Art. 25 (Online interface design & anti-dark patterns)",
            "compliant": is_clean,
            "violations_found": violations,
            "status": "APPROVED_CLEAN_UI" if is_clean else "DARK_PATTERNS_DETECTED",
        }

        digest = hashlib.sha256(json.dumps(report, sort_keys=True).encode("utf-8")).hexdigest().upper()
        report["audit_sha256"] = digest
        return is_clean, report

    def audit_minors_protection_policy(
        self,
        minor_access_allowed: bool,
        profiling_ads_enabled_for_minors: bool,
        high_privacy_by_default: bool,
        age_verification_method: str = "ZERO_KNOWLEDGE_PROOF_EUDI_WALLET",
    ) -> tuple[bool, dict[str, Any]]:
        """Audits minor safety protections and ad restrictions under Article 28."""
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Article 28(2): targeted advertising based on profiling of minors is strictly prohibited
        profiling_ad_violation = minor_access_allowed and profiling_ads_enabled_for_minors
        privacy_violation = minor_access_allowed and not high_privacy_by_default

        is_compliant = not (profiling_ad_violation or privacy_violation)

        audit = {
            "audited_at_iso": timestamp_iso,
            "article": "DSA Art. 28 (Protection of minors online)",
            "minor_access_allowed": minor_access_allowed,
            "profiling_ads_for_minors_disabled": not profiling_ads_enabled_for_minors,
            "high_privacy_by_default_enforced": high_privacy_by_default,
            "age_verification_method": age_verification_method,
            "compliant": is_compliant,
            "status": "MINOR_SAFETY_VERIFIED" if is_compliant else "VIOLATION_MINORS_AT_RISK",
        }

        digest = hashlib.sha256(json.dumps(audit, sort_keys=True).encode("utf-8")).hexdigest().upper()
        audit["audit_sha256"] = digest
        return is_compliant, audit


def main() -> None:
    parser = argparse.ArgumentParser(description="DSA Dark Patterns & Minors Guard")
    parser.parse_args()
    guard = DSADarkPatternsAndMinorsGuard()
    ui_clean, _ui_rep = guard.audit_ui_interface_design([
        {"name": "CookieBanner", "pattern_detected": "BALANCED_CHOICE_SYMMETRIC"},
        {"name": "SubscriptionCancel", "pattern_detected": "ONE_CLICK_UNSUBSCRIBE"},
    ])
    minor_clean, _minor_rep = guard.audit_minors_protection_policy(
        minor_access_allowed=True,
        profiling_ads_enabled_for_minors=False,
        high_privacy_by_default=True,
        age_verification_method="EUDI_WALLET_OVER_18_ZKP",
    )
    print(f"UI Clean: {ui_clean}, Minor Protection: {minor_clean}")


if __name__ == "__main__":
    main()
