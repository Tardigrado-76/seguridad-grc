"""
LSSI-CE Anti-Spam and Consent Manager Engine
Cumplimiento Ley 34/2002 (LSSI-CE) Art. 21 (Prohibición de envíos publicitarios no solicitados) y Art. 22 (Revocación y cookies).
Gestión de Doble Opt-in, lista de exclusión (opt-out) y trazabilidad de consentimientos electrónicos.
"""

import time
import hashlib
from typing import Dict, Any, Set, Optional


class LSSIAntiSpamConsentManager:
    def __init__(self):
        self.active_consents: Dict[str, Dict[str, Any]] = {}
        self.opt_out_registry: Set[str] = set()

    def register_double_optin_consent(self, email: str, ip_address: str, channel: str = "web_newsletter") -> Dict[str, Any]:
        """Registra consentimiento verificable bajo Art. 21 LSSI-CE tras doble opt-in."""
        email_clean = email.strip().lower()
        if email_clean in self.opt_out_registry:
            self.opt_out_registry.remove(email_clean)

        token = hashlib.sha256(f"{email_clean}:{time.time()}:{ip_address}".encode()).hexdigest()
        consent_record = {
            "email": email_clean,
            "ip_address": ip_address,
            "channel": channel,
            "timestamp": time.time(),
            "double_optin_confirmed": True,
            "consent_hash": token,
            "legal_clause": "Consentimiento expreso conforme a Ley 34/2002 Art. 21 y RGPD Art. 7"
        }
        self.active_consents[email_clean] = consent_record
        return consent_record

    def revoke_consent_optout(self, email: str, reason: str = "user_unsubscribe") -> Dict[str, Any]:
        """Procesa revocación inmediata conforme a Art. 21.2 LSSI-CE."""
        email_clean = email.strip().lower()
        if email_clean in self.active_consents:
            del self.active_consents[email_clean]
        
        self.opt_out_registry.add(email_clean)
        return {
            "email": email_clean,
            "status": "OPTED_OUT",
            "revocation_timestamp": time.time(),
            "reason": reason
        }

    def can_send_commercial_communications(self, email: str) -> bool:
        """Verifica si es legal enviar comunicaciones comerciales a dicho destinatario."""
        email_clean = email.strip().lower()
        if email_clean in self.opt_out_registry:
            return False
        return email_clean in self.active_consents
