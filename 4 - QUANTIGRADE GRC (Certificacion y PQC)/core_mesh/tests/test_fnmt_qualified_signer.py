"""
Tests for FnmtQualifiedSigner: Qualified electronic signatures for public administration dossiers.
"""
import pytest
from core_mesh.operational.fnmt_qualified_signer import (
    FnmtQualifiedSigner,
    PublicSectorSignerMeta,
    SignedPublicDossierPackage,
)


def test_sign_public_sector_dossier():
    signer = FnmtQualifiedSigner()
    signer_meta = PublicSectorSignerMeta(
        full_name="Maria Carmen Gonzalez Lopez",
        nif="01234567L",
        role_title="CISO / Responsable de Seguridad TIC",
        organism="Direccion General de Ciberseguridad",
        dir3_code="E05073401",
        certificate_issuer="FNMT-RCM AC Representacion",
        certificate_serial="5A7B8C9D10203040"
    )

    dossier_data = {
        "expediente_id": "EXP-ENS-2026-99",
        "evaluacion": "CONFORME ENS NIVEL ALTO",
        "fecha": "2026-10-27T23:00:00Z"
    }

    signed_pkg = signer.sign_dossier(dossier_data, signer_meta)

    assert isinstance(signed_pkg, SignedPublicDossierPackage)
    assert signed_pkg.is_valid is True
    assert signed_pkg.signer_meta.nif == "01234567L"
    assert "FNMT-RCM" in signed_pkg.signer_meta.certificate_issuer
    assert len(signed_pkg.signature_cades_sha256) == 64
    assert len(signed_pkg.rfc3161_timestamp_token) > 0


def test_verify_public_sector_signature_tamper_detection():
    signer = FnmtQualifiedSigner()
    signer_meta = PublicSectorSignerMeta(
        full_name="Carlos Ruiz",
        nif="98765432M",
        role_title="Auditor Interno",
        organism="Ayuntamiento de Madrid",
        dir3_code="L01280796",
        certificate_issuer="DNIe AC 004",
        certificate_serial="1234ABCD5678EF"
    )

    dossier_data = {"score": 100.0, "status": "APPROVED"}
    signed_pkg = signer.sign_dossier(dossier_data, signer_meta)

    # Valid check
    assert signer.verify_dossier(signed_pkg) is True

    # Tamper with the underlying dossier data
    signed_pkg.dossier_data["score"] = 50.0
    assert signer.verify_dossier(signed_pkg) is False
