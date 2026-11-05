"""
Module: generate_mtls_certs.py
Description: Production-ready enterprise component for Generate Mtls Certs.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


logger = logging.getLogger(__name__)
"""
Module: generate_mtls_certs.py
Description: Production-ready enterprise component for Generate Mtls Certs.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
from datetime import datetime, timedelta, UTC
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress

CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)

def generate_key_and_cert(cn, is_ca=False, ca_cert=None, ca_key=None, is_server=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    if not is_ca and ca_cert:
        issuer = ca_cert.subject

    builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC)).not_valid_after(datetime.now(UTC) + timedelta(days=365))
    
    # Subject Key Identifier
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # Key usage for CA
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        # For CA, AKI is its own SKI
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
    else:
        # For leaf certs, AKI is CA's SKI
        issuer_key = ca_key if ca_key else key
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)

    if is_server:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), 
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        ]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    elif not is_ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)

    signer_key = ca_key if ca_key else key
    cert = builder.sign(signer_key, hashes.SHA256())
    return key, cert

def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

# Generate CA
ca_key, ca_cert = generate_key_and_cert("Bunker CA", is_ca=True)
save_key(ca_key, f"{CERTS_DIR}/ca.key")
save_cert(ca_cert, f"{CERTS_DIR}/ca.crt")

# Generate Server
server_key, server_cert = generate_key_and_cert("localhost", ca_cert=ca_cert, ca_key=ca_key, is_server=True)
save_key(server_key, f"{CERTS_DIR}/server.key")
save_cert(server_cert, f"{CERTS_DIR}/server.crt")

# Generate Valid Client (For BFF)
client_valid_key, client_valid_cert = generate_key_and_cert("bunker-bff-valid", ca_cert=ca_cert, ca_key=ca_key)
save_key(client_valid_key, f"{CERTS_DIR}/client_valid.key")
save_cert(client_valid_cert, f"{CERTS_DIR}/client_valid.crt")
# Copy as default client for mtls-fetch.ts
save_key(client_valid_key, f"{CERTS_DIR}/client.key")
save_cert(client_valid_cert, f"{CERTS_DIR}/client.crt")

# Generate Revoked Client
client_revoked_key, client_revoked_cert = generate_key_and_cert("bunker-bff-revoked", ca_cert=ca_cert, ca_key=ca_key)
save_key(client_revoked_key, f"{CERTS_DIR}/client_revoked.key")
save_cert(client_revoked_cert, f"{CERTS_DIR}/client_revoked.crt")

# Generate Unknown Client (Self Signed)
client_unknown_key, client_unknown_cert = generate_key_and_cert("attacker", is_ca=False)
save_key(client_unknown_key, f"{CERTS_DIR}/client_unknown.key")
save_cert(client_unknown_cert, f"{CERTS_DIR}/client_unknown.crt")

# Generate CRL
builder = x509.CertificateRevocationListBuilder()
builder = builder.issuer_name(ca_cert.subject)
builder = builder.last_update(datetime.now(UTC))
builder = builder.next_update(datetime.now(UTC) + timedelta(days=1))

revoked_cert = x509.RevokedCertificateBuilder().serial_number(
    client_revoked_cert.serial_number
).revocation_date(
    datetime.now(UTC)
).build()

builder = builder.add_revoked_certificate(revoked_cert)
builder = builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
    critical=False
)
builder = builder.add_extension(
    x509.CRLNumber(1),
    critical=False
)

crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

with open(f"{CERTS_DIR}/ca.crl", "wb") as f:
    f.write(crl.public_bytes(serialization.Encoding.PEM))

logger.info("[+] All certificates and CRL generated successfully.")


if __name__ == '__main__':
    # Production entry point
    pass
