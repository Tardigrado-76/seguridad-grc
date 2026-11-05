"""
Test suite for MerkleBunker cryptographically verified evidence seals.
Tests dynamic HMAC secrets, SHA256 trees, and tamper detection.
"""

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
from core_mesh.business_execution.merkle_bunker import MerkleBunker, EvidenceSeal


def test_merkle_bunker_seal_and_verify():
    bunker = MerkleBunker(secret_key="TEST_SECRET_KEY_1234567890123456")
    evidences = {
        "ENS_POLICY": {"status": "ACTIVE", "version": "2.0"},
        "DORA_AUDIT": {"status": "PASSED", "score": 98.5}
    }
    
    seal = bunker.seal_audit_evidence(
        company_name="ACME Corp",
        frameworks=["ENS", "DORA"],
        evidences=evidences
    )
    assert isinstance(seal, EvidenceSeal)
    assert seal.company_name == "ACME Corp"
    assert len(seal.merkle_root) == 64
    assert len(seal.hmac_signature) == 64
    assert seal.pqc_ml_dsa_signature is not None
    assert len(seal.pqc_ml_dsa_signature) == 128
    assert seal.leaf_count == 2
    
    # Verification must succeed
    assert bunker.verify_seal(seal) is True


def test_merkle_bunker_detects_tampering():
    bunker = MerkleBunker(secret_key="TEST_SECRET_KEY_1234567890123456")
    evidences = {
        "DORA_AUDIT": {"status": "PASSED", "score": 100.0}
    }
    
    seal = bunker.seal_audit_evidence("ACME Corp", ["DORA"], evidences)
    
    # Tamper with the classical signature
    tampered_sig_seal = EvidenceSeal(
        seal_id=seal.seal_id,
        company_name=seal.company_name,
        timestamp_utc=seal.timestamp_utc,
        merkle_root=seal.merkle_root,
        leaf_count=seal.leaf_count,
        leaf_hashes=seal.leaf_hashes,
        frameworks=seal.frameworks,
        hmac_signature="0" * 64,
        pqc_ml_dsa_signature=seal.pqc_ml_dsa_signature
    )
    assert bunker.verify_seal(tampered_sig_seal) is False

    # Tamper with the PQC signature
    tampered_pqc_seal = EvidenceSeal(
        seal_id=seal.seal_id,
        company_name=seal.company_name,
        timestamp_utc=seal.timestamp_utc,
        merkle_root=seal.merkle_root,
        leaf_count=seal.leaf_count,
        leaf_hashes=seal.leaf_hashes,
        frameworks=seal.frameworks,
        hmac_signature=seal.hmac_signature,
        pqc_ml_dsa_signature="0" * 128
    )
    assert bunker.verify_seal(tampered_pqc_seal) is False

    # Tamper with the Merkle root
    tampered_root_seal = EvidenceSeal(
        seal_id=seal.seal_id,
        company_name=seal.company_name,
        timestamp_utc=seal.timestamp_utc,
        merkle_root="f" * 64,
        leaf_count=seal.leaf_count,
        leaf_hashes=seal.leaf_hashes,
        frameworks=seal.frameworks,
        hmac_signature=seal.hmac_signature,
        pqc_ml_dsa_signature=seal.pqc_ml_dsa_signature
    )
    assert bunker.verify_seal(tampered_root_seal) is False

    # Different secret key fails verification
    other_bunker = MerkleBunker(secret_key="DIFFERENT_UNAUTHORIZED_KEY_00000")
    assert other_bunker.verify_seal(seal) is False
