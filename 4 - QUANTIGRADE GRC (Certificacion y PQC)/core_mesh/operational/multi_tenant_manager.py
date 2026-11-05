"""Quantigrade GCR - Multi-Tenancy Enterprise Manager & BYOK Isolation.

Provides multi-tenant governance, Bring Your Own Key (BYOK) evidence segregation,
and strict quota/rate-limiting without requiring Docker containers.
100% native Python without Docker.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

class MultiTenantManager:
    """Manages enterprise tenants, segregated encryption keys (BYOK), and resource quotas."""

    def __init__(self, base_storage_dir: Optional[str] = None):
        self.base_dir = Path(base_storage_dir or "data/tenants")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.tenants: Dict[str, Dict[str, Any]] = {}
        self._request_windows: Dict[str, List[float]] = {}

    def register_tenant(
        self,
        tenant_id: str,
        organization_name: str,
        byok_key: Optional[str] = None,
        storage_quota_mb: float = 250.0,
        rate_limit_rpm: int = 120
    ) -> Dict[str, Any]:
        """Registers a new tenant with dedicated BYOK key and storage quota."""
        clean_id = tenant_id.strip().lower()
        if clean_id in self.tenants:
            raise ValueError(f"Tenant '{clean_id}' already registered.")

        # BYOK: Tenant-provided 256-bit key or auto-generated sovereign key
        encryption_key = byok_key or os.urandom(32).hex()
        
        tenant_folder = self.base_dir / clean_id
        tenant_folder.mkdir(parents=True, exist_ok=True)

        tenant_profile = {
            "tenant_id": clean_id,
            "organization_name": organization_name,
            "key_fingerprint": hashlib.sha256(encryption_key.encode("utf-8")).hexdigest()[:16],
            "raw_key": encryption_key,
            "storage_quota_bytes": int(storage_quota_mb * 1024 * 1024),
            "rate_limit_rpm": rate_limit_rpm,
            "consumed_bytes": 0,
            "created_at": time.time()
        }
        self.tenants[clean_id] = tenant_profile
        self._request_windows[clean_id] = []

        return {
            "tenant_id": clean_id,
            "organization_name": organization_name,
            "key_fingerprint": tenant_profile["key_fingerprint"],
            "storage_quota_mb": storage_quota_mb,
            "rate_limit_rpm": rate_limit_rpm
        }

    def check_rate_limit(self, tenant_id: str) -> bool:
        """Sliding-window rate limiter per tenant."""
        clean_id = tenant_id.strip().lower()
        if clean_id not in self.tenants:
            return False

        limit = self.tenants[clean_id]["rate_limit_rpm"]
        now = time.time()
        window = [t for t in self._request_windows.get(clean_id, []) if now - t < 60.0]
        
        if len(window) >= limit:
            return False

        window.append(now)
        self._request_windows[clean_id] = window
        return True

    def encrypt_evidence_byok(self, tenant_id: str, payload_data: Union[str, bytes]) -> Dict[str, Any]:
        """Encrypts evidence with tenant's BYOK key and appends HMAC-SHA256 authentication tag."""
        clean_id = tenant_id.strip().lower()
        if clean_id not in self.tenants:
            raise KeyError(f"Tenant '{clean_id}' not found.")

        raw_bytes = payload_data.encode("utf-8") if isinstance(payload_data, str) else payload_data
        
        # Check quota
        t_data = self.tenants[clean_id]
        if t_data["consumed_bytes"] + len(raw_bytes) > t_data["storage_quota_bytes"]:
            raise MemoryError(f"Storage quota exceeded for tenant '{clean_id}'.")

        key_bytes = t_data["raw_key"].encode("utf-8")
        
        # Stream-cipher emulation (XOR keystream derived via SHA-256 + HMAC-SHA256 for integrity)
        keystream = hashlib.sha256(key_bytes + b":ENC_STREAM").digest()
        cipher_bytes = bytearray(len(raw_bytes))
        for i in range(len(raw_bytes)):
            cipher_bytes[i] = raw_bytes[i] ^ keystream[i % len(keystream)]

        auth_tag = hmac.new(key_bytes, bytes(cipher_bytes), hashlib.sha256).hexdigest()
        t_data["consumed_bytes"] += len(raw_bytes)

        return {
            "tenant_id": clean_id,
            "ciphertext_b64": base64.b64encode(bytes(cipher_bytes)).decode("utf-8"),
            "auth_tag": auth_tag,
            "key_fingerprint": t_data["key_fingerprint"],
            "payload_size_bytes": len(raw_bytes)
        }

    def decrypt_evidence_byok(self, tenant_id: str, encrypted_envelope: Dict[str, Any]) -> str:
        """Decrypts and verifies authentication tag using tenant's BYOK key."""
        clean_id = tenant_id.strip().lower()
        if clean_id not in self.tenants:
            raise KeyError(f"Tenant '{clean_id}' not found.")

        t_data = self.tenants[clean_id]
        key_bytes = t_data["raw_key"].encode("utf-8")
        cipher_bytes = base64.b64decode(encrypted_envelope["ciphertext_b64"])
        stored_tag = encrypted_envelope["auth_tag"]

        expected_tag = hmac.new(key_bytes, cipher_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(stored_tag, expected_tag):
            raise PermissionError("BYOK HMAC Integrity Tag Mismatch: Data corrupted or tampered.")

        keystream = hashlib.sha256(key_bytes + b":ENC_STREAM").digest()
        plain_bytes = bytearray(len(cipher_bytes))
        for i in range(len(cipher_bytes)):
            plain_bytes[i] = cipher_bytes[i] ^ keystream[i % len(keystream)]

        return bytes(plain_bytes).decode("utf-8")

    def get_tenant_metrics(self, tenant_id: str) -> Dict[str, Any]:
        """Returns storage consumption and quota health."""
        clean_id = tenant_id.strip().lower()
        if clean_id not in self.tenants:
            raise KeyError(f"Tenant '{clean_id}' not found.")

        t = self.tenants[clean_id]
        quota = t["storage_quota_bytes"]
        used = t["consumed_bytes"]
        pct = (used / quota * 100.0) if quota > 0 else 0.0

        return {
            "tenant_id": clean_id,
            "organization_name": t["organization_name"],
            "consumed_bytes": used,
            "storage_quota_bytes": quota,
            "quota_usage_percentage": round(pct, 2),
            "rate_limit_rpm": t["rate_limit_rpm"],
            "status": "HEALTHY" if pct < 85.0 else "WARNING_QUOTA_HIGH"
        }
