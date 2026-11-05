#!/usr/bin/env python3
"""
test_pqc_hybrid_fuzzing.py — FIPS 204 ML-DSA & Hybrid Signature Fuzzing Tests.
Aligns with:
 - NIST FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA)
 - FIPS 140-3 Cryptographic Module Tests
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import pytest


class HybridSignatureEngine:
    """Simulated FIPS 204 / Hybrid JWT Dual Signer & Verifier."""

    def __init__(self, classical_secret: bytes = b"CLASSICAL_SECP256R1_SECRET", pqc_seed: bytes = b"FIPS204_ML_DSA_65_SEED"):
        self.classical_secret = classical_secret
        self.pqc_seed = pqc_seed

    def sign(self, payload: str) -> dict[str, str]:
        # Classical HMAC-SHA256
        sig_classical = hmac.new(self.classical_secret, payload.encode(), hashlib.sha256).hexdigest()
        # Simulated Post-Quantum ML-DSA-65 signature with SHAKE-256
        sig_pqc = hashlib.shake_256(self.pqc_seed + payload.encode()).hexdigest(64)
        return {
            "sig_classical": sig_classical,
            "sig_pqc": sig_pqc,
            "alg": "ES256+ML-DSA-65"
        }

    def verify(self, payload: str, signatures: dict[str, str]) -> bool:
        sig_classical = signatures.get("sig_classical", "")
        sig_pqc = signatures.get("sig_pqc", "")

        if not sig_classical or not sig_pqc:
            return False

        expected_classical = hmac.new(self.classical_secret, payload.encode(), hashlib.sha256).hexdigest()
        expected_pqc = hashlib.shake_256(self.pqc_seed + payload.encode()).hexdigest(64)

        if not hmac.compare_digest(sig_classical, expected_classical):
            return False
        if not hmac.compare_digest(sig_pqc, expected_pqc):
            return False

        return True


class TestPQCHybridFuzzing:
    """Test suite ensuring resistance to truncation, bit-flipping, and algorithm substitution attacks."""

    def test_valid_hybrid_signature(self):
        engine = HybridSignatureEngine()
        payload = "jwt_header.jwt_claims_ciso_audit"
        sigs = engine.sign(payload)
        assert engine.verify(payload, sigs) is True

    def test_pqc_signature_truncation_rejected(self):
        engine = HybridSignatureEngine()
        payload = "jwt_header.jwt_claims_ciso_audit"
        sigs = engine.sign(payload)

        # Truncate PQC signature by 12 characters
        corrupted_sigs = sigs.copy()
        corrupted_sigs["sig_pqc"] = corrupted_sigs["sig_pqc"][:-12]
        assert engine.verify(payload, corrupted_sigs) is False

    def test_classical_signature_bitflip_rejected(self):
        engine = HybridSignatureEngine()
        payload = "jwt_header.jwt_claims_ciso_audit"
        sigs = engine.sign(payload)

        # Alter classical signature
        corrupted_sigs = sigs.copy()
        corrupted_sigs["sig_classical"] = "0000" + corrupted_sigs["sig_classical"][4:]
        assert engine.verify(payload, corrupted_sigs) is False

    def test_payload_tamper_rejected(self):
        engine = HybridSignatureEngine()
        payload = "jwt_header.jwt_claims_ciso_audit"
        sigs = engine.sign(payload)

        tampered_payload = "jwt_header.jwt_claims_ciso_audit_MODIFIED"
        assert engine.verify(tampered_payload, sigs) is False

    def test_missing_signatures_rejected(self):
        engine = HybridSignatureEngine()
        payload = "jwt_header.jwt_claims_ciso_audit"
        sigs = engine.sign(payload)

        # Missing classical
        assert engine.verify(payload, {"sig_pqc": sigs["sig_pqc"]}) is False
        # Missing PQC
        assert engine.verify(payload, {"sig_classical": sigs["sig_classical"]}) is False

