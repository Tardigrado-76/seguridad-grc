import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Configuracion y Constantes
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUIREMENTS_PATH = Path(__file__).parent.parent / "requirements.txt"
TIMEOUT = 10

def fetch_cisa_kev():
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                return data.get("vulnerabilities", [])
    except urllib.error.URLError:
        pass
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        pass
    return []

def parse_requirements():
    if not REQUIREMENTS_PATH.exists():
        return []

    deps = []
    try:
        f = open(REQUIREMENTS_PATH, encoding="utf-8")
        lines = f.readlines()
        f.close()
    except UnicodeDecodeError:
        f = open(REQUIREMENTS_PATH, encoding="utf-16")
        lines = f.readlines()
        f.close()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Simple regex para capturar nombre de paquete
        match = re.match(r"^([a-zA-Z0-9_\-]+)", line)
        if match:
            deps.append(match.group(1).lower())
    return deps

def analyze_supply_chain() -> None:

    vulns = fetch_cisa_kev()
    if not vulns:
        sys.exit(1)


    deps = parse_requirements()

    found_vulns = False
    for vuln in vulns:
        product = vuln.get("product", "").lower()
        vendor = vuln.get("vendorProject", "").lower()

        for dep in deps:
            # Busqueda simple: si el nombre del paquete coincide con el producto o vendedor reportado en KEV
            if dep in product or dep in vendor:
                found_vulns = True

    if not found_vulns:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    analyze_supply_chain()
