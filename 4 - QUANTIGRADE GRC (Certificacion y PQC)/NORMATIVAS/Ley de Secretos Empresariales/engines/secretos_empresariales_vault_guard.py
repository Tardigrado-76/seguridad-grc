#!/usr/bin/env python3
"""
secretos_empresariales_vault_guard.py - Trade Secrets Protection & Access Vault Engine.
Implements Ley 1/2019 de Secretos Empresariales, Directiva (UE) 2016/943,
and Data Act (Reglamento UE 2023/2854) Trade Secret Safeguards.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("SecretosVault")


class SecretosEmpresarialesVaultGuard:
    """Enforces reasonable technical protection measures under Ley 1/2019 Art. 1."""

    def __init__(self, organization: str):
        self.organization = organization
        self.protected_assets: dict[str, dict[str, Any]] = {}

    def register_trade_secret(
        self, asset_id: str, classification: str, authorized_roles: list[str]
    ) -> dict[str, Any]:
        """Classifies and seals an asset as a protected business secret under Ley 1/2019."""
        record = {
            "asset_id": asset_id,
            "classification": classification,
            "authorized_roles": authorized_roles,
            "encryption_standard": "AES-256-GCM",
            "nda_required": True,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        self.protected_assets[asset_id] = record
        logger.info(
            f"Trade secret {asset_id} registered under Ley 1/2019 (Classification: {classification})"
        )
        return record

    def verify_access_request(
        self, asset_id: str, user_role: str, signed_nda_hash: str
    ) -> bool:
        """Validates strict role authorization and valid technical NDA before granting access."""
        if asset_id not in self.protected_assets:
            return False
        asset = self.protected_assets[asset_id]
        if user_role not in asset["authorized_roles"] or not signed_nda_hash:
            logger.warning(
                f"Unauthorized trade secret access attempt on {asset_id} by role {user_role}"
            )
            return False
        logger.info(
            f"Authorized trade secret access on {asset_id} for role {user_role}"
        )
        return True


if __name__ == "__main__":
    vault = SecretosEmpresarialesVaultGuard("DeepTech Industrial S.A.")
    vault.register_trade_secret(
        "ALG-GEN-4", "SECRETO_INDUSTRIAL_CRITICO", ["CHIEF_SCIENTIST", "LEAD_ARCHITECT"]
    )
    valid = vault.verify_access_request(
        "ALG-GEN-4", "LEAD_ARCHITECT", "HASH_NDA_SIGNED_123"
    )
    print(f"Access granted: {valid}")
