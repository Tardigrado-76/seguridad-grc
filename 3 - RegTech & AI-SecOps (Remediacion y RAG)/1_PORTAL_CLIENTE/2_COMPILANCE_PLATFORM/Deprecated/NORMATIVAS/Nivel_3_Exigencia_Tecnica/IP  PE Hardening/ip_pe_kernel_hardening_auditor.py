#!/usr/bin/env python3
"""
ip_pe_kernel_hardening_auditor.py — Infrastructure Protection & Kernel Security Policy Auditor.

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
from pathlib import Path
from typing import Any, Dict, List, Tuple


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
        "fs.protected_hardlinks": "1"
    }

    def audit_hardening_script(self, file_path: Path) -> List[Dict[str, Any]]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for param, expected in self.RECOMMENDED_SYSCTL_SETTINGS.items():
                if param not in content:
                    findings.append({
                        "parameter": param,
                        "expected_value": expected,
                        "severity": "MEDIUM",
                        "recommendation": f"Añadir la configuración sysctl {param}={expected} para bastionado del kernel."
                    })
        except Exception:
            pass
        return findings

    def scan_directory(self, target_path: Path) -> Dict[str, Any]:
        hardening_results = []
        files_scanned = 0

        for root, _, files in os.walk(target_path):
            if any(x in root for x in ['.venv', 'venv', '.git', 'reports']):
                continue
            for file in files:
                if file.endswith(('.sh', '.ps1', '.conf', 'sysctl.conf')):
                    fpath = Path(root) / file
                    files_scanned += 1
                    file_f = self.audit_hardening_script(fpath)
                    if file_f:
                        hardening_results.append({
                            "file": str(fpath.name),
                            "missing_parameters": file_f
                        })

        return {
            "files_scanned": files_scanned,
            "non_hardened_files_count": len(hardening_results),
            "findings_details": hardening_results,
            "is_hardened": len(hardening_results) == 0
        }


def save_evidence(data: Dict[str, Any], output_dir: Path) -> Tuple[Path, Path, str]:
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
    parser.add_argument("-i", "--input", type=str, default=None, help="Ruta al directorio de scripts de bastionado")
    parser.add_argument("-o", "--output", type=str, default=None, help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación")

    args = parser.parse_args()

    input_str = clean_path(args.input) if args.input else None
    if not input_str:
        input_str = input("Ingrese la ruta del directorio de bastionado [Defecto: .]: ").strip() or "."
    target_path = Path(clean_path(input_str)).resolve()

    if not target_path.exists():
        print(f"[-] Error: La ruta especificada no existe: {target_path}", file=sys.stderr)
        sys.exit(1)

    output_str = clean_path(args.output) if args.output else None
    if not output_str:
        output_str = "./reports"
    output_dir = Path(clean_path(output_str)).resolve()

    auditor = KernelHardeningAuditor()
    analysis = auditor.scan_directory(target_path)

    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis
    }

    json_p, md_p, sha_digest = save_evidence(payload, output_dir)
    print(f"[+] Auditoría de Bastionado de Infraestructura e IP PE Kernel completada.")
    print(f"    Archivos analizados: {analysis['files_scanned']}")
    print(f"    Archivos no bastionados completamente: {analysis['non_hardened_files_count']}")
    print(f"    Informe JSON: {json_p}")
    print(f"    Informe MD:   {md_p}")
    print(f"    Firma SHA-256: {sha_digest}")


if __name__ == "__main__":
    main()
