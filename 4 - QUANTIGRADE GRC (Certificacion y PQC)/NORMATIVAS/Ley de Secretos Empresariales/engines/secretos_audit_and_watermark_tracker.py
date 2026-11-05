"""
Secretos Audit and Watermark Tracker
Cumplimiento Ley 1/2019 de Secretos Empresariales (Art. 3 - Medidas Razonables de Protección).
Trazabilidad de accesos, marcas de agua dinámicas y registro inmutable de descargas.
"""

import hashlib
import json
import time
from typing import Dict, Any, List, Optional
from pathlib import Path


class SecretosAuditTracker:
    def __init__(self, audit_log_path: Optional[Path] = None):
        self.audit_log_path = audit_log_path or Path("secretos_audit_trail.jsonl")
        self._memory_log: List[Dict[str, Any]] = []

    def generate_watermark(self, document_id: str, user_id: str, purpose: str) -> Dict[str, Any]:
        """Genera metadata de marca de agua forense para un activo confidencial."""
        timestamp = time.time()
        raw_seed = f"{document_id}:{user_id}:{timestamp}:{purpose}".encode("utf-8")
        watermark_hash = hashlib.sha256(raw_seed).hexdigest()[:16].upper()
        
        return {
            "watermark_id": f"CONFIDENTIAL-{watermark_hash}",
            "document_id": document_id,
            "recipient": user_id,
            "timestamp": timestamp,
            "legal_notice": "INFORMACIÓN CONFIDENCIAL - Sujeto a Ley 1/2019 de Secretos Empresariales. Prohibida difusión no autorizada."
        }

    def record_access_event(self, user_id: str, document_id: str, action: str, ip_address: str = "127.0.0.1") -> Dict[str, Any]:
        """Registra un evento de acceso en el log de auditoría."""
        event = {
            "timestamp": time.time(),
            "user_id": user_id,
            "document_id": document_id,
            "action": action,
            "ip_address": ip_address,
            "checksum": hashlib.sha256(f"{user_id}:{document_id}:{action}:{time.time()}".encode()).hexdigest()
        }
        self._memory_log.append(event)
        return event

    def get_events_for_asset(self, document_id: str) -> List[Dict[str, Any]]:
        return [e for e in self._memory_log if e["document_id"] == document_id]
