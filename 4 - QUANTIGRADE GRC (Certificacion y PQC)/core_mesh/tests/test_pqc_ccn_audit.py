"""
Tests for PqcCcnAuditEngine: Auditing cryptography according to Guía CCN-STIC 893 (Transición Criptográfica Post-Cuántica).
"""
import pytest
from core_mesh.business_execution.pqc_ccn_audit import (
    PqcCcnAuditEngine,
    PqcAlgorithmStatus,
    PqcSuiteAuditReport,
)


def test_audit_approved_quantum_safe_suite():
    engine = PqcCcnAuditEngine()
    suite = {
        "signature_algorithm": "ML-DSA-87",
        "kem_algorithm": "ML-KEM-1024",
        "hybrid_mode": True,
        "classic_signature": "ECDSA_P384",
    }

    report = engine.evaluate_suite(suite)
    assert report.is_ccn_approved is True
    assert report.signature_status == PqcAlgorithmStatus.AUTORIZADO_CCN
    assert report.kem_status == PqcAlgorithmStatus.AUTORIZADO_CCN
    assert report.quantum_resistance_years_estimated >= 30


def test_audit_deprecated_legacy_suite():
    engine = PqcCcnAuditEngine()
    suite = {
        "signature_algorithm": "RSA-2048",
        "kem_algorithm": "ECDH_P256",
        "hybrid_mode": False,
    }

    report = engine.evaluate_suite(suite)
    assert report.is_ccn_approved is False
    assert report.signature_status == PqcAlgorithmStatus.OBSOLETO_CCN
    assert len(report.vulnerability_warnings) >= 1
    assert "Mosca" in report.vulnerability_warnings[0] or "cuantica" in report.vulnerability_warnings[0].lower()


def test_audit_stateful_hash_signatures_ccn():
    engine = PqcCcnAuditEngine()
    # LMS / XMSS for firmware / WORM verification
    suite = {
        "signature_algorithm": "LMS_SHA256",
        "kem_algorithm": "NONE",
        "hybrid_mode": False,
    }

    report = engine.evaluate_suite(suite)
    assert report.signature_status == PqcAlgorithmStatus.AUTORIZADO_CCN
    assert "firmware" in report.recommendations[0].lower() or "inmutable" in report.recommendations[0].lower()
