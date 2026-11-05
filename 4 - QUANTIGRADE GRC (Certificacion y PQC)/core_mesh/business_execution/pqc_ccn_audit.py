"""
PQC Audit Engine aligned with Guía CCN-STIC 893 (Transición Criptográfica Post-Cuántica).
Evaluates algorithmic strength, hybrid implementations, and deprecated cryptography
for the Spanish National Cryptologic Centre (CCN-CERT).
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar


class PqcAlgorithmStatus(str, Enum):
    AUTORIZADO_CCN = "AUTORIZADO_CCN"
    TRANSICIONAL_HIBRIDO = "TRANSICIONAL_HIBRIDO"
    CONDICIONADO = "CONDICIONADO"
    OBSOLETO_CCN = "OBSOLETO_CCN"


@dataclass
class PqcSuiteAuditReport:
    is_ccn_approved: bool
    signature_status: PqcAlgorithmStatus
    kem_status: PqcAlgorithmStatus
    quantum_resistance_years_estimated: int
    vulnerability_warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    evaluation_metadata: dict[str, Any] = field(default_factory=dict)


class PqcCcnAuditEngine:
    """
    Audits cryptographic deployments according to Guía CCN-STIC 893.
    Recognizes NIST FIPS 203, 204, 205 algorithms and stateful hash signatures.
    """

    # Guía CCN-STIC 893 Official Taxonomy
    APPROVED_SIGNATURES: ClassVar[set[str]] = {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "DILITHIUM2", "DILITHIUM3", "DILITHIUM5",
        "SLH-DSA-128", "SLH-DSA-192", "SLH-DSA-256", "SPHINCS+",
        "LMS_SHA256", "XMSS_SHA256",
    }

    APPROVED_KEMS: ClassVar[set[str]] = {
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "KYBER512", "KYBER768", "KYBER1024",
    }

    DEPRECATED_ALGORITHMS: ClassVar[set[str]] = {
        "RSA-1024", "RSA-2048", "ECDSA_P256", "ECDH_P256", "DSA-1024", "SHA-1", "MD5",
    }

    def evaluate_suite(self, suite: dict[str, Any]) -> PqcSuiteAuditReport:
        sig_alg = str(suite.get("signature_algorithm", "")).upper()
        kem_alg = str(suite.get("kem_algorithm", "")).upper()
        is_hybrid = bool(suite.get("hybrid_mode", False))

        warnings = []
        recomm = []

        # 1. Signature Evaluation
        if any(sig_alg.startswith(approved) for approved in self.APPROVED_SIGNATURES):
            sig_status = PqcAlgorithmStatus.AUTORIZADO_CCN
        elif sig_alg in self.DEPRECATED_ALGORITHMS:
            sig_status = PqcAlgorithmStatus.OBSOLETO_CCN
            warnings.append(f"Firma '{sig_alg}' vulnerable frente a ordenadores cuanticos (Teorema de Mosca).")
        else:
            sig_status = PqcAlgorithmStatus.CONDICIONADO
            warnings.append(f"Firma '{sig_alg}' no catalogada expresamente en CCN-STIC 893.")

        # 2. KEM Evaluation
        if kem_alg in ["NONE", "", "N/A"]:
            kem_status = PqcAlgorithmStatus.AUTORIZADO_CCN if sig_status == PqcAlgorithmStatus.AUTORIZADO_CCN else PqcAlgorithmStatus.CONDICIONADO
        elif any(kem_alg.startswith(approved) for approved in self.APPROVED_KEMS):
            kem_status = PqcAlgorithmStatus.AUTORIZADO_CCN
        elif kem_alg in self.DEPRECATED_ALGORITHMS:
            kem_status = PqcAlgorithmStatus.OBSOLETO_CCN
            warnings.append(f"KEM/Intercambio de claves '{kem_alg}' vulnerable a ataque 'Harvest Now, Decrypt Later'.")
        else:
            kem_status = PqcAlgorithmStatus.CONDICIONADO

        # Global Approval
        is_approved = (sig_status == PqcAlgorithmStatus.AUTORIZADO_CCN) and (
            kem_status == PqcAlgorithmStatus.AUTORIZADO_CCN
        )

        years_resistant = 30 if is_approved else (10 if is_hybrid else 0)

        # Recommendations
        if sig_alg.startswith(("LMS", "XMSS")):
            recomm.append("Uso autorizado por CCN-STIC 893 prioritariamente para firmware y sellado inmutable WORM.")
        if is_hybrid:
            recomm.append("Modo hibrido conforme a la recomendacion de transicion gradual del CCN-CERT.")
        if not is_approved:
            recomm.append("Migrar de inmediato a suites ML-DSA-87 y ML-KEM-1024 segun mandato ENS Nivel ALTO.")

        return PqcSuiteAuditReport(
            is_ccn_approved=is_approved,
            signature_status=sig_status,
            kem_status=kem_status,
            quantum_resistance_years_estimated=years_resistant,
            vulnerability_warnings=warnings,
            recommendations=recomm,
            evaluation_metadata={"guia_referencia": "CCN-STIC 893", "criterio": "ENS_ALTO"},
        )
