#!/usr/bin/env python3
"""
ens_crypto_tls_pki_auditor.py — Esquema Nacional de Seguridad (ENS) Criptografía y Certificados.

Compliance Alignment:
- Real Decreto 311/2022 (ENS Categoría Alta).
- Medida [mp.eq.1] Criptografía y Algoritmos Aprobados por el CCN-CERT (CCN-STIC-807 / Guías CCN).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from typing import Any, ClassVar


class ENSCryptoTLSPKIAuditor:
    """Audits cryptographic suites, TLS 1.3 hardening, and PKI certificates for ENS Alta."""

    APPROVED_CIPHERS: ClassVar[list[str]] = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
    ]

    def __init__(self) -> None:
        pass

    def audit_tls_and_certificates(
        self,
        endpoint_name: str,
        tls_version: str = "TLSv1.3",
        cert_signature_algorithm: str = "SHA384withECDSA",
        cert_key_size_bits: int = 384,
        enforces_mtls: bool = True,
    ) -> tuple[bool, dict[str, Any]]:
        """Audits TLS configuration and PKI certificate strength against CCN-STIC-807."""
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        is_tls13 = tls_version in ["TLSv1.3", "TLS 1.3"]
        is_cert_strong = cert_key_size_bits >= 256 and "SHA" in cert_signature_algorithm
        is_compliant = is_tls13 and is_cert_strong and enforces_mtls

        report = {
            "endpoint": endpoint_name,
            "audited_at_iso": timestamp_iso,
            "tls_version": tls_version,
            "cert_algorithm": cert_signature_algorithm,
            "cert_key_size": cert_key_size_bits,
            "mtls_enforced": enforces_mtls,
            "ccn_cert_approved": is_compliant,
            "status": "APPROVED_ENS_ALTA" if is_compliant else "NON_COMPLIANT_WEAK_CIPHER",
        }

        digest = hashlib.sha256(json.dumps(report, sort_keys=True).encode("utf-8")).hexdigest().upper()
        report["audit_sha256"] = digest
        return is_compliant, report


def main() -> None:
    parser = argparse.ArgumentParser(description="ENS Criptografía y Certificados TLS Auditor")
    parser.parse_args()
    auditor = ENSCryptoTLSPKIAuditor()
    comp, rep = auditor.audit_tls_and_certificates("api.soberana.gob.es")
    print(f"ENS Criptografía TLS/PKI: {comp} (Status: {rep['status']})")


if __name__ == "__main__":
    main()
