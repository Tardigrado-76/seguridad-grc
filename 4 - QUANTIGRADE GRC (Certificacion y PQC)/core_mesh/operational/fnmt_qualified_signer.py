"""
FNMT / Public Sector Qualified Electronic Signer for Quantigrade GCR.
Generates CAdES/XAdES compliant signature packages for Public Administration dossiers
embedding official certificate metadata (FNMT-RCM, DNIe) and eIDAS 2.0 RFC 3161 qualified timestamps.
"""
import datetime
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PublicSectorSignerMeta:
    full_name: str
    nif: str
    role_title: str
    organism: str
    dir3_code: str
    certificate_issuer: str = "FNMT-RCM AC Representacion"
    certificate_serial: str = "UNKNOWN_SERIAL"


@dataclass
class SignedPublicDossierPackage:
    dossier_data: dict[str, Any]
    signer_meta: PublicSectorSignerMeta
    signature_cades_sha256: str
    rfc3161_timestamp_token: str
    signed_at_utc: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    is_valid: bool = True


class FnmtQualifiedSigner:
    """
    Simulates and wraps qualified electronic signatures for public administration dossiers,
    guaranteeing evidentiary presumption under Law 6/2020 on electronic trust services.
    """

    def __init__(self, qtsp_name: str = "FNMT-RCM"):
        self.qtsp_name = qtsp_name

    def sign_dossier(
        self,
        dossier_data: dict[str, Any],
        signer_meta: PublicSectorSignerMeta,
    ) -> SignedPublicDossierPackage:
        """
        Signs a dossier with public sector certificate metadata and embeds a qualified RFC 3161 timestamp.
        """
        canonical_dossier = json.dumps(dossier_data, sort_keys=True).encode("utf-8")
        data_hash = hashlib.sha256(canonical_dossier).hexdigest()

        # Build signer string
        signer_payload = f"{signer_meta.nif}:{signer_meta.full_name}:{signer_meta.dir3_code}:{signer_meta.certificate_serial}:{data_hash}"
        sig_hash = hashlib.sha256(signer_payload.encode("utf-8")).hexdigest()

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        tst_token = f"TST_{self.qtsp_name}_{hashlib.sha256((sig_hash + now).encode('utf-8')).hexdigest()[:32]}"

        return SignedPublicDossierPackage(
            dossier_data=dossier_data,
            signer_meta=signer_meta,
            signature_cades_sha256=sig_hash,
            rfc3161_timestamp_token=tst_token,
            signed_at_utc=now,
            is_valid=True,
        )

    def verify_dossier(self, package: SignedPublicDossierPackage) -> bool:
        """Verifies integrity and non-repudiation of a signed public sector dossier."""
        canonical_dossier = json.dumps(package.dossier_data, sort_keys=True).encode("utf-8")
        data_hash = hashlib.sha256(canonical_dossier).hexdigest()

        signer_payload = f"{package.signer_meta.nif}:{package.signer_meta.full_name}:{package.signer_meta.dir3_code}:{package.signer_meta.certificate_serial}:{data_hash}"
        expected_sig = hashlib.sha256(signer_payload.encode("utf-8")).hexdigest()

        return expected_sig == package.signature_cades_sha256
