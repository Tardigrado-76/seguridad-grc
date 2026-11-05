import json
import os
import sys
import urllib.request

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUIREMENTS_PATH = os.path.join(os.path.dirname(__file__), "..", "requirements.txt")

def fetch_cisa_kev():
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "BunkerOS-Build-Pipeline"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data.get("vulnerabilities", [])
    except (urllib.error.URLError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        sys.exit(1)

def parse_requirements():
    if not os.path.exists(REQUIREMENTS_PATH):
        sys.exit(1)
    packages = []
    with open(REQUIREMENTS_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
            packages.append(pkg.lower())
    return packages

def main() -> None:
    vulns = fetch_cisa_kev()
    packages = parse_requirements()

    # KEV structure has "vendorProject" and "product"
    kev_products = {v.get("product", "").lower() for v in vulns}
    kev_vendors = {v.get("vendorProject", "").lower() for v in vulns}

    compromised = []
    for pkg in packages:
        # Cross-reference
        if pkg in kev_products or pkg in kev_vendors:
            compromised.append(pkg)

    if compromised:
        for _c in compromised:
            pass
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
