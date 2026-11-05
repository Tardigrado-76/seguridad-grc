import pytest
from core_mesh.business_execution.qualified_timestamp_anchor import QualifiedTimestampAnchor

def test_create_timestamp_request():
    anchor = QualifiedTimestampAnchor("FNMT")
    root = "a" * 64
    req = anchor.create_timestamp_request(root)

    assert req["version"] == 1
    assert req["messageImprint"]["hashedMessage"] == root
    assert req["messageImprint"]["hashAlgorithm"] == "2.16.840.1.101.3.4.2.1"
    assert req["certReq"] is True
    assert len(req["request_hash"]) == 64

def test_issue_and_verify_timestamp_token():
    anchor = QualifiedTimestampAnchor("FNMT")
    root = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
    req = anchor.create_timestamp_request(root, nonce=12345678)
    token = anchor.issue_qualified_timestamp_token(req, custom_time_iso="20261027220000Z")

    assert token["status"] == "GRANTED"
    assert token["qualified_provider"] == "Fábrica Nacional de Moneda y Timbre (FNMT-RCM)"
    assert "eIDAS Art. 41.2" in token["legal_presumption"]

    verification = anchor.verify_timestamp_token(token, root)
    assert verification["valid"] is True
    assert verification["certified_time"] == "20261027220000Z"
    assert verification["status"] == "QUALIFIED_TIMESTAMP_VERIFIED"

def test_verify_detects_mismatch_root():
    anchor = QualifiedTimestampAnchor("FNMT")
    root_original = "1" * 64
    root_different = "2" * 64

    req = anchor.create_timestamp_request(root_original)
    token = anchor.issue_qualified_timestamp_token(req)

    verification = anchor.verify_timestamp_token(token, root_different)
    assert verification["valid"] is False
    assert "Hash mismatch" in verification["reason"]

def test_verify_detects_tampered_signature():
    anchor = QualifiedTimestampAnchor("FNMT")
    root = "e" * 64
    req = anchor.create_timestamp_request(root)
    token = anchor.issue_qualified_timestamp_token(req)

    # Tamper signature
    token["signature_value"] = "0" * 96

    verification = anchor.verify_timestamp_token(token, root)
    assert verification["valid"] is False
    assert "signature is invalid" in verification["reason"]

def test_generate_judicial_corporate_defense_dossier():
    anchor = QualifiedTimestampAnchor("CAMERFIRMA")
    root = "f" * 64
    req = anchor.create_timestamp_request(root)
    token = anchor.issue_qualified_timestamp_token(req)

    dossier = anchor.generate_judicial_corporate_defense_dossier(
        company_name="Empresa Regulada Española S.A.",
        tax_id="A-28000000",
        evaluation_results={"score": 100.0, "status": "GREEN"},
        timestamp_token=token
    )

    assert "Artículo 31 bis" in dossier["legislation_basis"][0]
    assert dossier["company"]["name"] == "Empresa Regulada Española S.A."
    assert dossier["evidentiary_value"] == "PLENA PRUEBA DOCUMENTAL INDUBITADA (RFC 3161 / WORM MERKLE)"
    assert len(dossier["dossier_hash"]) == 64
