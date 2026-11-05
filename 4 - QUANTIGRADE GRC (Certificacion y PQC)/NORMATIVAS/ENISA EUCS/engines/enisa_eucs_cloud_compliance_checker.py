#!/usr/bin/env python3
"""enisa_eucs_cloud_compliance_checker.py — ENISA EUCS Cloud Cybersecurity Certification Evaluator.

Compliance Alignment:
 - ENISA EU Cloud Cybersecurity Certification Scheme (EUCS): Levels Basic, Substantial, High
 - EU Cybersecurity Act (Reglamento UE 2019/881)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, ClassVar


def clean_path(path_str: str) -> str:
    """Sanitiza y limpia cadenas de rutas de comillas y espacios residuales."""
    if not path_str:
        return ""
    cleaned = path_str.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()
    return cleaned


class ENISAEUCSComplianceChecker:
    """Inspecciona artefactos de despliegue en la nube para verificar cumplimiento del esquema EUCS de ENISA."""

    EUCS_HIGH_REQUIREMENTS: ClassVar[list[str]] = [
        "eu_sovereignty_clause",
        "data_residency_eu",
        "hsm_key_management",
        "isolated_tenant_compute",
        "immutable_audit_logs",
    ]

    def audit_cloud_manifest(self, file_path: Path) -> dict[str, Any]:
        missing_reqs = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            for req in self.EUCS_HIGH_REQUIREMENTS:
                if req not in content:
                    missing_reqs.append(req)
        except (OSError, UnicodeDecodeError):
            missing_reqs = list(self.EUCS_HIGH_REQUIREMENTS)

        return {
            "file": file_path.name,
            "missing_eucs_high_requirements": missing_reqs,
            "is_eucs_high_compliant": len(missing_reqs) == 0,
        }

    def scan_directory(self, target_path: Path) -> dict[str, Any]:
        manifest_results = []
        files_scanned = 0

        for root, _, files in os.walk(target_path):
            if any(x in root for x in [".venv", "venv", ".git", "reports"]):
                continue
            for file in files:
                if file.endswith((".tf", ".yaml", ".yml", ".json")):
                    fpath = Path(root) / file
                    files_scanned += 1
                    res = self.audit_cloud_manifest(fpath)
                    manifest_results.append(res)

        return {
            "files_scanned": files_scanned,
            "eucs_compliant_manifests_count": sum(1 for r in manifest_results if r["is_eucs_high_compliant"]),
            "manifest_results": manifest_results,
            "overall_eucs_compliant": all(r["is_eucs_high_compliant"] for r in manifest_results) if manifest_results else False,
        }


def save_evidence(data: dict[str, Any], output_dir: Path) -> tuple[Path, Path, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"enisa_eucs_cloud_report_{ts}.json"
    md_path = output_dir / f"enisa_eucs_cloud_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest().upper()

    data_with_hash = dict(data)
    data_with_hash["report_sha256"] = sha256_hash

    json_path.write_text(json.dumps(data_with_hash, indent=2, ensure_ascii=False), encoding="utf-8")

    md_content = f"""# ENISA EUCS Cloud Cybersecurity Scheme Evidence Report

- **Timestamp (UTC):** `{data['timestamp']}`
- **Execution Mode:** `{'DRY-RUN (Simulation)' if data['dry_run'] else 'PRODUCTION'}`
- **Target Path:** `{data['target_path']}`
- **Cloud Manifests Scanned:** `{data['analysis']['files_scanned']}`
- **EUCS High Compliant Manifests:** `{data['analysis']['eucs_compliant_manifests_count']}`
- **Overall EUCS Compliant:** `{data['analysis']['overall_eucs_compliant']}`
- **SHA-256 Checksum:** `{sha256_hash}`

## EUCS Manifest Evaluation Details
```json
{json.dumps(data['analysis']['manifest_results'], indent=2)}
```
"""
    md_path.write_text(md_content, encoding="utf-8")
    return json_path, md_path, sha256_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluador ENISA EUCS del Esquema de Certificación Cloud.")
    parser.add_argument("-i", "--input", type=str, default=None, help="Ruta al directorio de manifiestos cloud")
    parser.add_argument("-o", "--output", type=str, default=None, help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación")

    args = parser.parse_args()

    input_str = clean_path(args.input) if args.input else None
    if not input_str:
        input_str = input("Ingrese la ruta del directorio de manifiestos cloud [Defecto: .]: ").strip() or "."
    target_path = Path(clean_path(input_str)).resolve()

    if not target_path.exists():
        sys.exit(1)

    output_str = clean_path(args.output) if args.output else None
    if not output_str:
        output_str = "./reports"
    output_dir = Path(clean_path(output_str)).resolve()

    checker = ENISAEUCSComplianceChecker()
    analysis = checker.scan_directory(target_path)

    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis,
    }

    _json_p, _md_p, _sha_digest = save_evidence(payload, output_dir)


if __name__ == "__main__":
    main()
