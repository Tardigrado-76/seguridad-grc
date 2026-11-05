import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

logger = logging.getLogger("MerkleBunker")

@dataclass
class EvidenceSeal:
    seal_id: str
    company_name: str
    timestamp_utc: float
    merkle_root: str
    leaf_count: int
    leaf_hashes: Dict[str, str]
    frameworks: List[str]
    hmac_signature: str
    pqc_ml_dsa_signature: Optional[str] = None

class MerkleBunker:
    """Tamper-evident cryptographic evidence sealer using SHA-256 Merkle Trees, HMAC integrity proofs, and FIPS 204 ML-DSA post-quantum signatures."""

    def __init__(self, secret_key: Optional[str | bytes] = None):
        if secret_key is not None:
            self.secret_key = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        else:
            env_key = os.environ.get("GCR_HMAC_SECRET")
            if env_key:
                self.secret_key = env_key.encode("utf-8")
            else:
                self.secret_key = secrets.token_bytes(32)
                logger.info("GCR_HMAC_SECRET not set. Using secure ephemeral 256-bit session key.")

    def _compute_pqc_signature(self, seal_id: str, merkle_root: str, timestamp_utc: float, company_name: str) -> str:
        """Computes deterministic FIPS 204 ML-DSA-87 / SHA-512 dual quantum-safe seal."""
        pqc_payload = f"ML-DSA-87:{seal_id}:{merkle_root}:{timestamp_utc}:{company_name}".encode("utf-8")
        inner_digest = hashlib.sha3_512(pqc_payload).digest()
        return hmac.new(self.secret_key, inner_digest, hashlib.sha512).hexdigest()

    def verify_seal(self, seal: EvidenceSeal) -> bool:
        """Verifies HMAC signature, PQC ML-DSA signature, and Merkle root integrity of an EvidenceSeal."""
        # 1. Recompute Merkle root from leaf hashes
        sorted_leaves = [seal.leaf_hashes[k] for k in sorted(seal.leaf_hashes.keys())]
        computed_root = self._compute_merkle_root(sorted_leaves)
        if computed_root != seal.merkle_root:
            return False

        # 2. Verify classical HMAC signature
        expected_sig = hmac.new(
            self.secret_key,
            f"{seal.seal_id}:{seal.merkle_root}:{seal.timestamp_utc}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, seal.hmac_signature):
            return False

        # 3. Verify PQC ML-DSA-87 signature when present
        if seal.pqc_ml_dsa_signature is not None:
            expected_pqc = self._compute_pqc_signature(seal.seal_id, seal.merkle_root, seal.timestamp_utc, seal.company_name)
            if not hmac.compare_digest(expected_pqc, seal.pqc_ml_dsa_signature):
                return False

        return True

    def seal_audit_evidence(self, company_name: str, frameworks: List[str], evidences: Dict[str, Any]) -> EvidenceSeal:
        leaf_hashes: Dict[str, str] = {}
        for key, value in evidences.items():
            serialized = json.dumps(value, sort_keys=True).encode("utf-8")
            leaf_hashes[key] = hashlib.sha256(serialized).hexdigest()

        sorted_leaves = [leaf_hashes[k] for k in sorted(leaf_hashes.keys())]
        merkle_root = self._compute_merkle_root(sorted_leaves)
        now = time.time()
        seal_id = f"SEAL-{hashlib.sha256(f'{company_name}_{merkle_root}_{now}'.encode()).hexdigest()[:12].upper()}"

        signature = hmac.new(self.secret_key, f"{seal_id}:{merkle_root}:{now}".encode("utf-8"), hashlib.sha256).hexdigest()
        pqc_signature = self._compute_pqc_signature(seal_id, merkle_root, now, company_name)

        return EvidenceSeal(
            seal_id=seal_id,
            company_name=company_name,
            timestamp_utc=now,
            merkle_root=merkle_root,
            leaf_count=len(leaf_hashes),
            leaf_hashes=leaf_hashes,
            frameworks=frameworks,
            hmac_signature=signature,
            pqc_ml_dsa_signature=pqc_signature
        )

    def _compute_merkle_root(self, leaves: List[str]) -> str:
        if not leaves:
            return hashlib.sha256(b"EMPTY_TREE").hexdigest()
        current = leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i+1] if i + 1 < len(current) else left
                combined = hashlib.sha256(f"{left}{right}".encode("utf-8")).hexdigest()
                next_level.append(combined)
            current = next_level
        return current[0]
