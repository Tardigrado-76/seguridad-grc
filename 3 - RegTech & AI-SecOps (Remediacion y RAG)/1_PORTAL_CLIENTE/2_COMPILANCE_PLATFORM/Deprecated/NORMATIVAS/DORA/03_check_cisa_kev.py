import logging
#!/usr/bin/env python3
"""
check_cisa_kev.py - Gatekeeper y Auditor de Vulnerabilidades CISA KEV (ENS Alto / NIS2 / DORA).

Cumplimiento Regulatorio:
-------------------------
- ENS (Nivel Alto): Art. 12 (Gestión de Vulnerabilidades y Actualizaciones de Seguridad).
- NIS2 (Directiva UE 2022/2555): Art. 21(2)(e) (Seguridad en la Adquisición, Desarrollo y Mantenimiento).
- DORA (Reglamento UE 2022/2554): Art. 10 y Art. 28 (Supervisión Continua del Riesgo TIC y Terceros).
- NIST SP 800-53 Rev. 5: SI-2 (Flaw Remediation) & RA-5 (Vulnerability Monitoring and Scanning).

Descripción:
------------
Verifica la cadena de suministro y dependencias de software contrastándolas contra el catálogo oficial
de Vulnerabilidades Conocidas Explotadas de la CISA (Known Exploited Vulnerabilities - CISA KEV).
Aplica una política de compilación/despliegue segura (*Fail-Secure Gatekeeper*).

Uso:
----
  python check_cisa_kev.py --requirements requirements.txt --output-dir ./kev_reports
  python check_cisa_kev.py --fail-secure --format both
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("CISA_KEV_Gatekeeper")

CISA_KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HTTP_TIMEOUT_SECONDS = 15


@dataclass
class VulnerableDependencyAlert:
    """Alerta de coincidencia con el catálogo CISA KEV."""

    package_name: str
    cve_id: str
    vulnerability_name: str
    vendor_project: str
    product_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    severity_rating: str = "CRITICAL_EXPLOITED_IN_WILD"


@dataclass
class CISAKEVReport:
    """Reporte completo de la auditoría CISA KEV."""

    audit_id: str
    timestamp: str
    requirements_file: str
    total_packages_checked: int
    cisa_kev_total_catalog_size: int
    vulnerable_matches_count: int
    integrity_hash: str
    alerts: List[Dict[str, Any]]
    fail_secure_triggered: bool
    compliance_verdict: str


class CISAKEVScanner:
    """Auditor y Gatekeeper de dependencias contra el catálogo CISA KEV."""

    def __init__(self, requirements_path: Path, fail_secure: bool = True):
        self.requirements_path = requirements_path
        self.fail_secure = fail_secure

    def parse_requirements(self) -> Set[str]:
        """Lee y extrae los nombres limpios de dependencias de requirements.txt."""
        if not self.requirements_path.exists():
            logger.warning(f"No se encontró el archivo de requerimientos: {self.requirements_path}")
            return set()

        packages: Set[str] = set()
        try:
            with open(self.requirements_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue

                    # Eliminar versiones y operadores (==, >=, <=, ~=, >, <, [)
                    clean_name = re.split(r"[=><~\[;]", line)[0].strip().lower()
                    if clean_name:
                        packages.add(clean_name)
        except Exception as e:
            logger.error(f"Error al leer el archivo de requerimientos {self.requirements_path}: {e}")
            if self.fail_secure:
                raise

        return packages

    def fetch_cisa_kev_feed(self) -> Tuple[List[Dict[str, Any]], int]:
        """Descarga el catálogo actualizado en vivo desde CISA.gov."""
        logger.info(f"Conectando a CISA KEV Feed: {CISA_KEV_API_URL}...")
        try:
            req = urllib.request.Request(
                CISA_KEV_API_URL,
                headers={"User-Agent": "BunkerOS-Compliance-Auditor/2.0 (ENS-Alto-NIS2)"},
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise urllib.error.HTTPError(
                        CISA_KEV_API_URL, response.status, "Respuesta HTTP no OK", response.headers, None
                    )
                raw_data = json.loads(response.read().decode("utf-8"))
                vulns = raw_data.get("vulnerabilities", [])
                logger.info(f"Catálogo CISA KEV cargado exitosamente ({len(vulns)} vulnerabilidades activas).")
                return vulns, len(vulns)

        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError) as e:
            logger.error(f"Error de red o procesamiento del feed CISA KEV: {e}")
            if self.fail_secure:
                logger.critical("Política Fail-Secure activa: Se requiere abortar el despliegue al no verificar KEV.")
                raise ConnectionError(f"Imposible validar feed CISA KEV en modo Fail-Secure: {e}")
            return [], 0

    def run_audit(self) -> CISAKEVReport:
        """Ejecuta el cruzamiento entre paquetes locales y el catálogo CISA KEV."""
        audit_id = f"KEV-AUDIT-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        packages = self.parse_requirements()
        cisa_vulns, catalog_size = self.fetch_cisa_kev_feed()

        matched_alerts: List[VulnerableDependencyAlert] = []

        for vuln in cisa_vulns:
            product = vuln.get("product", "").strip().lower()
            vendor = vuln.get("vendorProject", "").strip().lower()
            cve = vuln.get("cveID", "DESCONOCIDO")

            for pkg in packages:
                if pkg == product or pkg == vendor or (len(pkg) > 4 and pkg in product):
                    matched_alerts.append(
                        VulnerableDependencyAlert(
                            package_name=pkg,
                            cve_id=cve,
                            vulnerability_name=vuln.get("vulnerabilityName", "Vulnerabilidad CISA KEV"),
                            vendor_project=vuln.get("vendorProject", "N/A"),
                            product_name=vuln.get("product", "N/A"),
                            date_added=vuln.get("dateAdded", "N/A"),
                            short_description=vuln.get("shortDescription", "Sin descripción previa."),
                            required_action=vuln.get("requiredAction", "Actualizar a versión parcheada."),
                            due_date=vuln.get("dueDate", "N/A"),
                        )
                    )

        vuln_count = len(matched_alerts)
        fail_triggered = (vuln_count > 0) or (catalog_size == 0 and self.fail_secure)
        verdict = "APROBADO_SIN_VULNERABILIDADES_KEV" if vuln_count == 0 else "RECHAZADO_VULNERABILIDAD_EXPLOTADA_EN_USO"

        summary = f"{audit_id}|{len(packages)}|{vuln_count}|{verdict}"
        integrity_hash = hashlib.sha256(summary.encode("utf-8")).hexdigest()

        return CISAKEVReport(
            audit_id=audit_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            requirements_file=str(self.requirements_path),
            total_packages_checked=len(packages),
            cisa_kev_total_catalog_size=catalog_size,
            vulnerable_matches_count=vuln_count,
            integrity_hash=integrity_hash,
            alerts=[asdict(a) for a in matched_alerts],
            fail_secure_triggered=fail_triggered,
            compliance_verdict=verdict,
        )

    def export_json(self, report: CISAKEVReport, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Informe CISA KEV JSON exportado en: {output_path}")

    def export_markdown(self, report: CISAKEVReport, output_path: Path) -> None:
        badge = "✅ COMPILACIÓN PERMITIDA (SIN KEV CRÍTICOS)" if report.vulnerable_matches_count == 0 else "🚨 BLOQUEO FAIL-SECURE (VULNERABILIDAD EXPLOTADA ACTIVAMENTE)"

        md_content = f"""# Reporte de Auditoría CISA KEV Gatekeeper (ENS Alto / NIS2 / DORA)

**ID Auditoría:** `{report.audit_id}`  
**Archivo Requerimientos:** `{report.requirements_file}`  
**Fecha de Inspección:** {report.timestamp}  
**Dictamen de Seguridad:** {badge}  
**Hash de Integridad:** `{report.integrity_hash[:16]}...`  

---

## 1. Resumen de Análisis de Cadena de Suministro

- **Paquetes Locales Verificados:** {report.total_packages_checked}
- **Vulnerabilidades en Catálogo CISA KEV:** {report.cisa_kev_total_catalog_size}
- **Coincidencias Críticas Explotadas en Producción:** {report.vulnerable_matches_count} ⚠️
- **Política Fail-Secure Activada:** `{"SÍ" if report.fail_secure_triggered else "NO"}`

---

## 2. Detalle de Dependencias Afectadas (Explotables en el Mundo Real)

"""
        if report.vulnerable_matches_count == 0:
            md_content += "✅ **Ninguna de las dependencias analizadas se encuentra registrada en el catálogo de vulnerabilidades activas CISA KEV.**\n"
        else:
            md_content += "| Paquete Afectado | CVE ID | Nombre Vulnerabilidad | Acción Obligatoria CISA | Fecha Límite Parche |\n"
            md_content += "|------------------|--------|------------------------|-------------------------|---------------------|\n"
            for alert in report.alerts:
                md_content += f"| `{alert['package_name']}` | **{alert['cve_id']}** | {alert['vulnerability_name']} | {alert['required_action']} | `{alert['due_date']}` |\n"

        md_content += f"""

---

## 3. Exigencias Normativas y de Hardening

> **ENS Alto Art. 12 & NIST SP 800-53 SI-2:** La presencia de vulnerabilidades con exploit activo en el mercado (*Known Exploited Vulnerabilities*) imposibilita el despliegue a producción y requiere parcheado inmediato.

---
*Generado por `check_cisa_kev.py` el {report.timestamp}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Informe CISA KEV Markdown exportado en: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gatekeeper y Auditor CISA KEV de Cadena de Suministro (ENS Alto Art. 12 / NIS2 Art. 21 / DORA Art. 10)."
    )
    parser.add_argument(
        "-r",
        "--requirements",
        type=Path,
        default=Path("requirements.txt"),
        help="Ruta al archivo requirements.txt a auditar (default: requirements.txt).",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("./kev_audit_reports"),
        help="Directorio donde se guardarán los informes JSON y Markdown.",
    )
    parser.add_argument(
        "--fail-secure",
        action="store_true",
        default=True,
        help="Habilita política Fail-Secure (devuelve exit status 1 si hay fallos o indisponibilidad de red).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "both"],
        default="both",
        help="Formato de exportación del reporte (default: both).",
    )

    args = parser.parse_args()

    try:
        scanner = CISAKEVScanner(args.requirements, fail_secure=args.fail_secure)
        report = scanner.run_audit()

        out_json = args.output_dir / f"{report.audit_id}_kev_report.json"
        out_md = args.output_dir / f"{report.audit_id}_kev_report.md"

        if args.format in ("json", "both"):
            scanner.export_json(report, out_json)
        if args.format in ("markdown", "both"):
            scanner.export_markdown(report, out_md)

        if report.vulnerable_matches_count > 0:
            logger.warning(f"SE DETECTARON {report.vulnerable_matches_count} VULNERABILIDADES KEV EN LAS DEPENDENCIAS.")
            sys.exit(1)
        else:
            logger.info("Auditoría CISA KEV superada sin coincidencias vulnerables.")
            sys.exit(0)

    except Exception as e:
        logger.critical(f"Fallo en Gatekeeper CISA KEV: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
