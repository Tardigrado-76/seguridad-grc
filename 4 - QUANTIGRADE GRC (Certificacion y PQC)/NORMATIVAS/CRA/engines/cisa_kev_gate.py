"""
Module: cisa_kev_gate.py
Description: Production-ready enterprise component for Cisa Kev Gate.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


import logging
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

#!/usr/bin/env python3
"""
CISA KEV Gate - Phase Pre-Build Fail-Secure validation.
"""

import sys
import json
import urllib.request
import urllib.error
import re
import os

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUIREMENTS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "requirements.txt")

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"
YELLOW = "\033[93m"

def parse_requirements(filepath: str) -> set:
    packages = set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # Strip versions and modifiers (==, >=, <=, ~, >, <, [)
                # re.split will split at the first occurrence of these characters
                base_name = re.split(r'[=><~\[]', line)[0].strip().lower()
                if base_name:
                    packages.add(base_name)
    except OSError as e:
        logger.info(f"{RED}[CRITICAL] Fallo al leer {filepath}: {e}{RESET}")
        sys.exit(1)
        
    return packages

def fetch_cisa_kev() -> dict:
    logger.info("[*] Descargando catálogo CISA KEV...")
    try:
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": "BunkerOS/1.0 Pre-Build Gate"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data
    except urllib.error.URLError as e:
        logger.info(f"{RED}[CRITICAL] Error de red al contactar CISA KEV: {e}{RESET}")
        logger.info(f"{RED}[!] Aplicando Fail-Secure: Se bloquea el build por imposibilidad de validación.{RESET}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.info(f"{RED}[CRITICAL] Error al decodificar el JSON de CISA KEV: {e}{RESET}")
        logger.info(f"{RED}[!] Aplicando Fail-Secure: Se bloquea el build por formato corrupto.{RESET}")
        sys.exit(1)

def main():
    local_packages = parse_requirements(REQUIREMENTS_PATH)
    if not local_packages:
        logger.info(f"{YELLOW}[!] No se detectaron paquetes en {REQUIREMENTS_PATH}.{RESET}")
        sys.exit(0)
        
    cisa_data = fetch_cisa_kev()
    vulnerabilities = cisa_data.get("vulnerabilities", [])
    
    compromised = []
    
    for vuln in vulnerabilities:
        product = vuln.get("product", "").strip().lower()
        vendor = vuln.get("vendorProject", "").strip().lower()
        
        for pkg in local_packages:
            if pkg == product or pkg == vendor:
                compromised.append({
                    "package": pkg,
                    "cve": vuln.get("cveID", "UNKNOWN"),
                    "description": vuln.get("shortDescription", "No description")
                })
                
    if compromised:
        logger.info(f"\n{RED}" + "="*80)
        logger.info("CRITICAL SUPPLY CHAIN SECURITY ALERT:")
        logger.info("Se han detectado dependencias locales en el catálogo CISA KEV:")
        for alert in compromised:
            logger.info(f"  [!] Librería: {alert['package']}")
            logger.info(f"      CVE: {alert['cve']}")
            logger.info(f"      Descripción: {alert['description']}")
            logger.info("-" * 60)
        logger.info("="*80 + f"{RESET}\n")
        logger.info(f"{RED}[!] Aplicando Fail-Secure: Compilación ABORTADA. (Exit Code 1){RESET}")
        sys.exit(1)
        
    logger.info(f"{GREEN}[OK] Validación completada. Ninguna dependencia local figura en el catálogo CISA KEV. (Exit Code 0){RESET}")
    sys.exit(0)

if __name__ == "__main__":
    main()
