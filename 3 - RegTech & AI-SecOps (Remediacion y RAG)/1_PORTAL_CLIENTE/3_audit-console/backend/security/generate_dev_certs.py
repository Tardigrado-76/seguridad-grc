import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate_authenticode_dev_pfx(output_path: str, password: str) -> None:
    """Genera un certificado auto-firmado de desarrollo configurado para Firma de Código (Authenticode),
    empaquetado como archivo .pfx (PKCS#12) protegido por contraseña.
    Requisito P-003 (CRA) y P-006 (Rotación <= 199 días).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BunkerOS Dev Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "BunkerOS Dev EV Authenticode Cert"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject,
    ).issuer_name(
        issuer,
    ).public_key(
        private_key.public_key(),
    ).serial_number(
        x509.random_serial_number(),
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc),
    ).not_valid_after(
        # Válido por 199 días para cumplir con directrices CRA/ENS
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=199),
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
        critical=True,
    ).sign(private_key, hashes.SHA384())

    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"BunkerOS Code Signing Dev",
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(pfx_data)


if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "..", "security", "artifacts")
    out_file = os.path.abspath(os.path.join(out_dir, "dev_authenticode.pfx"))
    cert_password = os.getenv("PFX_PASSWORD", "bunker_pfx_dev_password_123!")

    generate_authenticode_dev_pfx(out_file, cert_password)
