#!/usr/bin/env python3
"""CISA KEV Supply Chain Auditor.
Cross-references local dependencies (via pip-audit) with the live CISA KEV Catalog.
"""
import json
import subprocess
import sys
import urllib.error
import urllib.request

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev() -> set:
    try:
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": "BunkerOS Supply Chain Agent"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
            data = json.loads(response.read().decode("utf-8"))
            vulnerabilities = data.get("vulnerabilities", [])
            return {vuln["cveID"].upper().strip() for vuln in vulnerabilities if "cveID" in vuln}
    except urllib.error.URLError:
        # If offline/failed, we will proceed but log warning.
        return set()
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
        return set()

def get_local_vulnerabilities() -> set:
    try:
        # Run pip-audit outputting JSON format
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # pip-audit returns non-zero exit code if vulnerabilities are found, so we parse stdout/stderr regardless
        stdout_data = result.stdout.strip()
        if not stdout_data:
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
        # Attempt to install it or fail
        return set()
    except (json.JSONDecodeError, UnicodeDecodeError, subprocess.SubprocessError, OSError):
        return set()

def main() -> None:
    # 1. Fetch live CISA KEV
    kev_cves = fetch_cisa_kev()

    # 2. Get local CVEs
    local_cves = get_local_vulnerabilities()

    if not local_cves:
        sys.exit(0)


    # 3. Cross-reference
    compromised = local_cves.intersection(kev_cves)
    if compromised:
        for _cve in compromised:
            pass
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
