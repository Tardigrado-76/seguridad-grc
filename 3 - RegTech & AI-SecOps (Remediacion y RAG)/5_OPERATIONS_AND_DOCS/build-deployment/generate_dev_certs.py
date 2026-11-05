"""
Module: generate_dev_certs.py
Description: Production-ready enterprise component for Generate Dev Certs.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


logger = logging.getLogger(__name__)
"""
Module: generate_dev_certs.py
Description: Production-ready enterprise component for Generate Dev Certs.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import datetime
import argparse
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.serialization import pkcs12

def generate_authenticode_dev_pfx(output_path: str, password: str, org_name: str, common_name: str, days: int):
    """
    Genera un certificado auto-firmado de desarrollo configurado para Firma de Código (Authenticode),
    empaquetado como archivo .pfx (PKCS#12) protegido por contraseña.
    """
    logger.info(f"Generando clave RSA-4096 para firma de código EV simulada...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    logger.info("Configurando extensiones de firma de código (Code Signing)...")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Válido por la cantidad de días especificada
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
        critical=True
    ).sign(private_key, hashes.SHA384())

    logger.info(f"Empaquetando en PKCS#12 (PFX)...")
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=common_name.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    # Crear directorio si no existe
    dir_name = os.path.dirname(output_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
        
    with open(output_path, "wb") as f:
        f.write(pfx_data)
        
    logger.info(f"[+] Certificado PFX guardado exitosamente en: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generador genérico independiente de certificados de desarrollo Authenticode (PFX).")
    parser.add_argument("-o", "--output", default="./dev_authenticode.pfx", help="Ruta de salida del archivo PFX (por defecto: ./dev_authenticode.pfx).")
    parser.add_argument("-p", "--password", default="cert_dev_password_123!", help="Contraseña para proteger el archivo PFX.")
    parser.add_argument("--org", default="Generic Dev Root CA", help="Nombre de la Organización para el certificado.")
    parser.add_argument("--cn", default="Dev EV Authenticode Cert", help="Common Name (CN) para el certificado.")
    parser.add_argument("-d", "--days", type=int, default=199, help="Días de validez del certificado (por defecto: 199).")
    
    args = parser.parse_args()
    generate_authenticode_dev_pfx(args.output, args.password, args.org, args.cn, args.days)
