#!/usr/bin/env python3
"""
test_eidas2_compliance.py - TDD & Verification Suite for eIDAS 2.0 Compliance.
Verifies EUDI Wallet, Qualified Electronic Signatures (QES), Attestation of Attributes (EAA),
and the EIDAS2Evaluator scoring 100.0% GREEN.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add directories to path for imports
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "engines"))
sys.path.insert(0, str(BASE_DIR / "evaluators"))

# Ensure base compliance manager is also in path
CENTRAL_MGR = Path("e:/PROYECTOS IA/PRODUCTION READY/100/GITHUB/QUANTIGRADE GRC")
if CENTRAL_MGR.exists():
    sys.path.insert(0, str(CENTRAL_MGR))

from eidas2 import EIDAS2Evaluator
from eidas2_eaa_attribute_attestator import EAAAttributeAttestator
from eidas2_eudi_wallet_manager import EUDIWalletManager
from eidas2_qes_signature_engine import QESSignatureEngine
from src.evaluators.base import RAGStatus


def test_eudi_wallet_issuance_and_selective_disclosure(tmp_path: Path) -> None:
    """Verifies Art. 6a EUDI Wallet credential lifecycle and selective disclosure."""
    mgr = EUDIWalletManager(wallet_holder_id="eu.citizen.es.001", output_dir=str(tmp_path))
    res = mgr.issue_verifiable_id(national_id="12345678Z", country_code="ES")
    cred_id = res["credential_id"]

    assert cred_id.startswith("PID-ES-")
    assert res["pid"]["loa"] == "HIGH"
    assert res["pid"]["secure_hardware_backed"] is True

    # Test selective disclosure
    presentation = mgr.selective_disclosure_presentation(
        credential_id=cred_id,
        requested_claims=["holder_id", "loa"],
        relying_party_id="urn:relying-party:bank-spain"
    )
    assert presentation["selective_disclosure"] is True
    assert presentation["eidas2_compliant"] is True
    assert "holder_id" in presentation["disclosed_claims"]
    assert "national_id_hash" not in presentation["disclosed_claims"]


def test_qes_signature_engine(tmp_path: Path) -> None:
    """Verifies Arts. 25-26 Qualified Electronic Signatures generation and verification."""
    engine = QESSignatureEngine(qtsp_identifier="ES-QTSP-FNMT-CERES", output_dir=str(tmp_path))
    sample_doc = b"Contract terms under EU law."
    signer = "CN=Juan Perez, O=Tech S.L., C=ES"

    qes_pkg = engine.sign_document_qes(sample_doc, signer)
    assert qes_pkg["legal_status"] == "QUALIFIED_ELECTRONIC_SIGNATURE_ART25"
    assert qes_pkg["document_sha256"] is not None

    # Verify signature
    is_valid, msg = engine.verify_qes_signature(sample_doc, qes_pkg)
    assert is_valid is True
    assert "VALID" in msg


def test_eaa_attribute_attestator() -> None:
    """Verifies Art. 45a Electronic Attestation of Attributes (EAA)."""
    attestator = EAAAttributeAttestator(authority_id="urn:es:universidad:upm")
    attestation = attestator.issue_attestation(
        holder_id="eu.citizen.es.001",
        attribute_type="eu.europa.ec.eudi.education.diploma",
        attributes={"degree": "Master Computer Science", "honors": True},
        is_qualified=True
    )

    assert attestation["is_qualified_eaa"] is True
    assert attestation["proof"]["type"] == "Eidas2AttestationProof2024"

    # Verify attestation
    is_valid, msg = attestator.verify_attestation(attestation)
    assert is_valid is True
    assert "VALID" in msg


def test_eidas2_evaluator_scores_100_percent() -> None:
    """Verifies EIDAS2Evaluator produces a 100.0% compliance score with GREEN status."""
    evaluator = EIDAS2Evaluator(target_path=str(BASE_DIR), company_name="EuroCorp S.A.")
    result = evaluator.evaluate()

    assert result.framework_name == "EIDAS_2_0"
    assert result.compliance_score == 100.0
    assert result.rag_status == RAGStatus.GREEN
    assert len(result.findings) == 4
    for finding in result.findings:
        assert finding.passed is True
