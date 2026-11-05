"""
Auditor Token Guard - Ephemeral Read-Only Auditor Access Portal
Permite la emisión y verificación de tokens efímeros firmados criptográficamente para
organismos supervisores y auditores externos (AENOR, BdE, CNMV, BSI).
Garantiza acceso de solo lectura estricto a las matrices de evidencias y sellos Merkle,
bloqueando cualquier capacidad de remediación o alteración de estado.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class AuditorSession:
    auditor_id: str
    organization: str
    created_at: float
    expires_at: float
    allowed_frameworks: List[str]
    is_read_only: bool = True
    can_execute_remediation: bool = False


class AuditorTokenGuard:
    """Gestor de autenticación efímera y control de acceso para auditorías regulatorias externas."""

    PREFIX = "aud_tok_"

    def __init__(self, secret_key: Optional[str] = None):
        if secret_key:
            self._secret_key = secret_key.encode("utf-8")
        else:
            env_key = os.environ.get("GCR_AUDITOR_HMAC_SECRET")
            if env_key:
                self._secret_key = env_key.encode("utf-8")
            else:
                self._secret_key = secrets.token_bytes(32)

    def create_token(
        self,
        auditor_id: str,
        organization: str,
        validity_seconds: int = 86400,
        allowed_frameworks: Optional[List[str]] = None
    ) -> str:
        """Emite un token efímero firmado con HMAC-SHA256 y TTL definido."""
        now = time.time()
        token_id = secrets.token_hex(8)
        
        payload = {
            "tid": token_id,
            "aud": auditor_id,
            "org": organization,
            "iat": now,
            "exp": now + validity_seconds,
            "fwk": allowed_frameworks or ["*"],
            "ro": True
        }

        serialized = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(serialized).decode("utf-8").rstrip("=")
        
        signature = hmac.new(
            self._secret_key,
            f"{self.PREFIX}{token_id}.{payload_b64}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        return f"{self.PREFIX}{token_id}.{payload_b64}.{signature}"

    def verify_token(self, token_str: str) -> Optional[AuditorSession]:
        """Verifica la firma, integridad y vigencia temporal del token de auditor."""
        if not token_str or not token_str.startswith(self.PREFIX):
            return None

        parts = token_str.split(".")
        if len(parts) != 3:
            return None

        header_part, payload_b64, signature = parts
        
        # 1. Verificar firma HMAC
        expected_sig = hmac.new(
            self._secret_key,
            f"{header_part}.{payload_b64}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, signature):
            return None

        # 2. Decodificar y validar payload
        try:
            # Añadir padding si fue recortado
            rem = len(payload_b64) % 4
            if rem > 0:
                payload_b64 += "=" * (4 - rem)
            
            raw_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
            claims = json.loads(raw_json)
        except Exception:
            return None

        # 3. Comprobar expiración temporal
        now = time.time()
        if now > claims.get("exp", 0):
            return None

        return AuditorSession(
            auditor_id=claims.get("aud", "UNKNOWN"),
            organization=claims.get("org", "INDEPENDENT_AUDITOR"),
            created_at=claims.get("iat", now),
            expires_at=claims.get("exp", now),
            allowed_frameworks=claims.get("fwk", ["*"]),
            is_read_only=True,
            can_execute_remediation=False
        )
