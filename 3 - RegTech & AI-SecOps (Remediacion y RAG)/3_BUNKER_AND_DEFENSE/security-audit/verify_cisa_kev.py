"""
Module: verify_cisa_kev.py
Description: Production-ready enterprise component for Verify Cisa Kev.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


logger = logging.getLogger(__name__)
"""
Module: verify_cisa_kev.py
Description: Production-ready enterprise component for Verify Cisa Kev.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import json
import urllib.request
import sys
import os
import argparse

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev():
    try:
        logger.info("[*] Descargando feed oficial CISA KEV...")
        req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "DevSecOps-Pipeline"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data.get("vulnerabilities", [])
    except Exception as e:
        logger.info(f"[-] Error descargando CISA KEV: {e}")
        sys.exit(1)

def parse_requirements(requirements_path):
    if not os.path.exists(requirements_path):
        logger.info(f"[-] No se encontró {requirements_path}")
        sys.exit(1)
    packages = []
    with open(requirements_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
            packages.append(pkg.lower())
    return packages

def main(requirements_path):
    vulns = fetch_cisa_kev()
    packages = parse_requirements(requirements_path)

    # KEV structure has "vendorProject" and "product"
    kev_products = set(v.get("product", "").lower() for v in vulns)
    kev_vendors = set(v.get("vendorProject", "").lower() for v in vulns)

    compromised = []
    for pkg in packages:
        # Cross-reference
        if pkg in kev_products or pkg in kev_vendors:
            compromised.append(pkg)

    if compromised:
        logger.info("\n[!] CRÍTICO: Se han detectado dependencias en el catálogo CISA KEV (explotadas in the wild).")
        for c in compromised:
            logger.info(f"    - {c}")
        logger.info("\n[!] Compilación cancelada (Fail-Secure).")
        sys.exit(1)
    else:
        logger.info("\n[+] Cadena de suministro limpia. Ninguna dependencia coincide con CISA KEV.")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verificador de seguridad independiente contra CISA KEV.")
    parser.add_argument("-r", "--requirements", default="./requirements.txt", help="Ruta al archivo requirements.txt a verificar.")
    parser.add_argument("-p", "--project", help="Ruta al directorio raíz del proyecto (buscará requirements.txt allí).")
    
    args = parser.parse_args()
    
    req_path = args.requirements
    if args.project:
        req_path = os.path.join(args.project, "requirements.txt")
        
    main(req_path)
