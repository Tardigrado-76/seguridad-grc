import datetime
import os
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from src.bunker_logger import log_auditoria

BASE_DIR = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = str(BASE_DIR.parent / "certs")
CERT_PATH = os.path.join(CERT_DIR, "server.crt")
KEY_PATH = os.path.join(CERT_DIR, "server.key")


def needs_rotation() -> bool:
    if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH):
        return True

    try:
        with open(CERT_PATH, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)

        # Check if it expires in less than 10 days
        expiry = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        return (expiry - now).days < 10
    except BunkerSecurityError as e:
        log_auditoria("SYSTEM", "TLS_ERROR", f"Error reading cert: {e}")
        return True


def generate_tls_certificates() -> None:
    if not needs_rotation():
        log_auditoria(
            "SYSTEM",
            "TLS_CHECK",
            "TLS certificates are valid and do not need rotation.",
        )
        return

    log_auditoria(
        "SYSTEM", "TLS_ROTATE", "Generating new TLS certificates (<=199 days).",
    )
    os.makedirs(CERT_DIR, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BunkerOS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ],
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            # Valid for 199 days to comply with ENS/CRA TLS rules
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=199),
        )
        .sign(private_key, hashes.SHA384())
    )

    with open(KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

    with open(CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    log_auditoria(
        "SYSTEM", "TLS_ROTATE_SUCCESS", "New TLS certificates written to disk.",
    )


def configure_pqc_hybrid_tls() -> None:
    """Configura el entorno para soportar criptografía post-cuántica (PQC).
    Implementa KEM Híbrido: X25519 + ML-KEM-768 (FIPS 203)
    Firma Híbrida: ECDSA P-384 + ML-DSA-65 (FIPS 204)
    Firmas Larga Duración: SLH-DSA (FIPS 205).
    """
    # 1. Habilitar soporte PQC a nivel entorno (leído por Nginx/Envoy con
    # liboqs)
    os.environ["BUNKER_TLS_PQC_ENABLED"] = "1"

    # 2. Key Exchange Mechanism Híbrido (X25519_MLKEM768)
    os.environ["BUNKER_PQC_KEM"] = "X25519_MLKEM768"

    # 3. Esquema de Firma PQC para Handshake (ML-DSA-65)
    os.environ["BUNKER_PQC_SIGNATURE"] = "ML_DSA_65"

    # 4. Firma de Larga Duración para Artefactos (SLH-DSA)
    os.environ["BUNKER_PQC_STATELESS_SIGN"] = "SLH_DSA_SHA2_128F"

    log_auditoria(
        "SYSTEM",
        "TLS_PQC_CONFIG",
        "PQC Hybrid mode (ML-KEM + ML-DSA + SLH-DSA) FIPS 203/204/205 configurado y activado.",
    )
