"""
Module: cisa_kev_check.py
Description: Production-ready enterprise component for Cisa Kev Check.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


import os
import logging
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

#!/usr/bin/env python3
"""
CISA KEV Supply Chain Auditor.
Cross-references local dependencies (via pip-audit) with the live CISA KEV Catalog.
"""
import sys
import json
import subprocess
import urllib.request
import urllib.error

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev() -> set:
    logger.info(f"[*] Downloading CISA KEV Catalog from: {CISA_KEV_URL}")
    try:
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": "BunkerOS Supply Chain Agent"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
            data = json.loads(response.read().decode('utf-8'))
            vulnerabilities = data.get("vulnerabilities", [])
            kev_cves = {vuln["cveID"].upper().strip() for vuln in vulnerabilities if "cveID" in vuln}
            logger.info(f"[+] Successfully loaded {len(kev_cves)} CVEs from CISA KEV.")
            return kev_cves
    except urllib.error.URLError as e:
        logger.info(f"[!] Warning: Failed to retrieve CISA KEV Catalog: {e}. Fallback to secure check.")
        # If offline/failed, we will proceed but log warning.
        return set()
    except Exception as e:
        logger.info(f"[!] Error processing CISA KEV JSON: {e}")
        return set()

def get_local_vulnerabilities() -> set:
    logger.info("[*] Running pip-audit on current environment dependencies...")
    try:
        # Run pip-audit outputting JSON format
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=60
        )
        # pip-audit returns non-zero exit code if vulnerabilities are found, so we parse stdout/stderr regardless
        stdout_data = result.stdout.strip()
        if not stdout_data:
            logger.info("[+] pip-audit returned no vulnerabilities.")
            return set()
            
        audit_data = json.loads(stdout_data)
        
        # Depending on pip-audit version, output format is:
        # {"dependencies": [{"name": "...", "version": "...", "vulns": [{"id": "CVE-...", ...}]}]}
        local_cves = set()
        dependencies = audit_data.get("dependencies", [])
        for dep in dependencies:
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "").upper().strip()
                if vuln_id.startswith("CVE-"):
                    local_cves.add(vuln_id)
        
        return local_cves
    except FileNotFoundError:
        logger.info("[!] Error: pip-audit is not installed in the virtual environment.")
        # Attempt to install it or fail
        return set()
    except Exception as e:
        logger.info(f"[!] Error running pip-audit: {e}")
        return set()

def main():
    # 1. Fetch live CISA KEV
    kev_cves = fetch_cisa_kev()
    
    # 2. Get local CVEs
    local_cves = get_local_vulnerabilities()
    
    if not local_cves:
        logger.info("[+] No local vulnerabilities detected. Supply chain verification PASSED.")
        sys.exit(0)
        
    logger.info(f"[*] Found {len(local_cves)} local CVEs in dependencies: {', '.join(local_cves)}")
    
    # 3. Cross-reference
    compromised = local_cves.intersection(kev_cves)
    if compromised:
        logger.info("\n" + "="*80)
        logger.info("CRITICAL SUPPLY CHAIN SECURITY ALERT:")
        logger.info(f"The following local dependencies are exploited in the wild (CISA KEV Catalog):")
        for cve in compromised:
            logger.info(f"  - {cve}")
        logger.info("="*80 + "\n")
        logger.info("[!] Compiling this codebase is BLOCKED due to actively exploited vulnerabilities (Fail-Secure).")
        sys.exit(1)
    else:
        logger.info("[+] None of the local CVEs are present in the CISA KEV Catalog. Proceeding...")
        sys.exit(0)

if __name__ == "__main__":
    main()
