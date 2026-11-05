#!/usr/bin/env python3
"""ip_kernel_hardening_auditor.py — Infrastructure Protection & Kernel Security Policy Auditor.

Compliance Alignment:
 - DISA STIG Linux / Windows Hardening Guidelines
 - CIS Benchmarks Level 2: Kernel & Network Hardening
 - ENS RD 311/2022: Medida [op.exp.5] Bastionado de Sistemas y Perímetros
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


def clean_path(path_str: str) -> str:
    """Sanitiza y limpia cadenas de rutas de comillas y espacios residuales."""
    if not path_str:
        return ""
    cleaned = path_str.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()
    return cleaned


class KernelHardeningAuditor:
    """Inspecciona sysctl, reglas de firewall y scripts de bastionado para verificar parámetros críticos del kernel."""

    RECOMMENDED_SYSCTL_SETTINGS = {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "kernel.randomize_va_space": "2",
        "fs.protected_symlinks": "1",
        "fs.protected_hardlinks": "1",
    }

    def audit_hardening_script(self, file_path: Path) -> list[dict[str, Any]]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for param, expected in self.RECOMMENDED_SYSCTL_SETTINGS.items():
                if param not in content:
                    findings.append({
                        "parameter": param,
                        "expected_value": expected,
                        "severity": "MEDIUM",
                        "recommendation": f"Añadir la configuración sysctl {param}={expected} para bastionado del kernel.",
                    })
        except Exception:
            pass
        return findings

    def scan_directory(self, target_path: Path | str) -> dict[str, Any]:
        target = Path(target_path)
        hardening_results = []
        files_scanned = 0

        for root, _, files in os.walk(target):
            if any(x in root for x in [".venv", "venv", ".git", "reports", "__pycache__"]):
                continue
            for file in files:
                if file.endswith((".sh", ".ps1", ".conf", "sysctl.conf")):
                    fpath = Path(root) / file
                    files_scanned += 1
                    file_f = self.audit_hardening_script(fpath)
                    if file_f:
                        hardening_results.append({
                            "file": str(fpath.name),
                            "missing_parameters": file_f,
                        })

        return {
            "files_scanned": files_scanned,
            "non_hardened_files_count": len(hardening_results),
            "findings_details": hardening_results,
            "is_hardened": len(hardening_results) == 0,
        }


def save_evidence(data: dict[str, Any], output_dir: Path) -> tuple[Path, Path, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"ip_pe_kernel_hardening_report_{ts}.json"
    md_path = output_dir / f"ip_pe_kernel_hardening_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest().upper()

    data_with_hash = dict(data)
    data_with_hash["report_sha256"] = sha256_hash

    json_path.write_text(json.dumps(data_with_hash, indent=2, ensure_ascii=False), encoding="utf-8")

    md_content = f"""# Infrastructure Protection & Kernel Security Policy Evidence Report

- **Timestamp (UTC):** `{data['timestamp']}`
- **Execution Mode:** `{'DRY-RUN (Simulation)' if data['dry_run'] else 'PRODUCTION'}`
- **Target Path:** `{data['target_path']}`
- **Hardening Scripts Scanned:** `{data['analysis']['files_scanned']}`
- **Non-Hardened Scripts:** `{data['analysis']['non_hardened_files_count']}`
- **Kernel Policy Hardened:** `{data['analysis']['is_hardened']}`
- **SHA-256 Checksum:** `{sha256_hash}`

## Hardening Audit Findings
```json
{json.dumps(data['analysis']['findings_details'], indent=2)}
```
"""
    md_path.write_text(md_content, encoding="utf-8")
    return json_path, md_path, sha256_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="Auditor de Bastionado del Kernel e Infraestructura (IP PE Hardening).")
    parser.add_argument("-i", "--input", type=str, default=".", help="Ruta al directorio de scripts de bastionado")
    parser.add_argument("-o", "--output", type=str, default="./reports", help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación")

    args = parser.parse_args()
    target_path = Path(clean_path(args.input)).resolve()
    output_dir = Path(clean_path(args.output)).resolve()

    auditor = KernelHardeningAuditor()
    analysis = auditor.scan_directory(target_path)

    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis,
    }

    save_evidence(payload, output_dir)


if __name__ == "__main__":
    main()

