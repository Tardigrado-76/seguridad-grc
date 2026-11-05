#!/usr/bin/env python3
"""
rgpd_data_breach_auditor.py — RGPD Art. 33-34 Data Breach Notification & Risk Assessment Auditor.

Compliance Alignment:
 - RGPD (Reglamento UE 2016/679): Art. 33 (Notificación de brecha a la AEPD en 72h) y Art. 34 (Comunicación a interesados)
 - LOPDGDD (Ley Orgánica 3/2018): Garantía de Derechos Digitales
"""


from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, ClassVar

logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)


def clean_path(path_str: str) -> str:
    """Sanitiza y limpia cadenas de rutas de comillas y espacios residuales."""
    if not path_str:
        return ""
    cleaned = path_str.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()
    return cleaned


class RGPDDataBreachAuditor:
    """Audita procedimientos de respuesta a incidentes de brechas de datos personales según RGPD Art. 33 y 34."""

    REQUIRED_BREACH_FIELDS: ClassVar[list[str]] = [
        "incident_id",
        "detection_timestamp",
        "affected_data_categories",
        "affected_data_subjects_count",
        "aepd_notification_status",
        "risk_to_rights_rating",
    ]

    def audit_breach_record(self, record_path: Path) -> dict[str, Any]:
        """Ejecuta la logica de audit_breach_record."""
        findings = []
        try:
            content = record_path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)
            records = data if isinstance(data, list) else [data]

            for idx, r in enumerate(records, 1):
                missing = [f for f in self.REQUIRED_BREACH_FIELDS if f not in r]
                if missing:
                    findings.append({
                        "record": idx,
                        "missing_fields": missing,
                        "severity": "HIGH",
                        "recommendation": "Completar campos obligatorios de brecha de datos para notificación AEPD en 72h."
                    })
        except Exception as err:
            findings.append({"error": str(err)})

        return {
            "file": record_path.name,
            "findings": findings,
            "is_compliant": len(findings) == 0
        }

    def scan_directory(self, target_path: Path) -> dict[str, Any]:
        """Ejecuta la logica de scan_directory."""
        breach_audits = []
        files_scanned = 0

        for root, _, files in os.walk(target_path):
            if any(x in root for x in ['.venv', 'venv', '.git', 'reports']):
                continue
            for file in files:
                if "breach" in file.lower() or "incidente" in file.lower() or "rgpd" in file.lower():
                    if file.endswith(('.json', '.yaml', '.yml')):
                        fpath = Path(root) / file
                        files_scanned += 1
                        res = self.audit_breach_record(fpath)
                        breach_audits.append(res)

        return {
            "files_scanned": files_scanned,
            "audited_breach_records_count": len(breach_audits),
            "audit_results": breach_audits,
            "overall_rgpd_compliant": all(b["is_compliant"] for b in breach_audits) if breach_audits else False
        }


def save_evidence(data: dict[str, Any], output_dir: Path) -> tuple[Path, Path, str]:
    """Ejecuta la logica de save_evidence."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"rgpd_data_breach_report_{ts}.json"
    md_path = output_dir / f"rgpd_data_breach_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest().upper()

    data_with_hash = dict(data)
    data_with_hash["report_sha256"] = sha256_hash

    json_path.write_text(json.dumps(data_with_hash, indent=2, ensure_ascii=False), encoding="utf-8")

    md_content = f"""# RGPD Art. 33-34 Data Breach & AEPD Notification Evidence Report

- **Timestamp (UTC):** `{data['timestamp']}`
- **Execution Mode:** `{'DRY-RUN (Simulation)' if data['dry_run'] else 'PRODUCTION'}`
- **Target Path:** `{data['target_path']}`
- **Breach Records Scanned:** `{data['analysis']['files_scanned']}`
- **RGPD Art. 33/34 Compliant:** `{data['analysis']['overall_rgpd_compliant']}`
- **SHA-256 Checksum:** `{sha256_hash}`

## Audit Details
```json
{json.dumps(data['analysis']['audit_results'], indent=2)}
```
"""
    md_path.write_text(md_content, encoding="utf-8")
    return json_path, md_path, sha256_hash


def main() -> None:
    """Ejecuta la logica de main."""
    parser = argparse.ArgumentParser(description="Auditor RGPD Art. 33-34 de Notificación de Brechas a la AEPD.")
    parser.add_argument("-i", "--input", type=str, default=None, help="Ruta al directorio de registros de incidentes de privacidad")
    parser.add_argument("-o", "--output", type=str, default=None, help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación")

    args = parser.parse_args()

    input_str = clean_path(args.input) if args.input else None
    if not input_str:
        input_str = input("Ingrese la ruta del directorio de registros de brechas [Defecto: .]: ").strip() or "."
    target_path = Path(clean_path(input_str)).resolve()

    if not target_path.exists():
        logger.error(f"[ERROR] Error: La ruta especificada no existe: {target_path}")
        sys.exit(1)

    output_str = clean_path(args.output) if args.output else None
    if not output_str:
        output_str = "./reports"
    output_dir = Path(clean_path(output_str)).resolve()

    auditor = RGPDDataBreachAuditor()
    analysis = auditor.scan_directory(target_path)

    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis
    }

    json_p, md_p, sha_digest = save_evidence(payload, output_dir)
    logger.info("[+] Auditoría RGPD Art. 33-34 de Brechas de Datos AEPD completada.")
    logger.info(f"    Registros de brechas analizados: {analysis['audited_breach_records_count']}")
    logger.info(f"    Conformidad RGPD:                {analysis['overall_rgpd_compliant']}")
    logger.info(f"    Informe JSON: {json_p}")
    logger.info(f"    Informe MD:   {md_p}")
    logger.info(f"    Firma SHA-256: {sha_digest}")


if __name__ == "__main__":
    main()
