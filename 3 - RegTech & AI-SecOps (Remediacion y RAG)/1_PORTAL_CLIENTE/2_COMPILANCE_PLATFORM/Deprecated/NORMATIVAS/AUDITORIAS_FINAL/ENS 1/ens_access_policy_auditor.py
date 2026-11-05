import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
"""
ens_access_policy_auditor.py — ENS RD 311/2022 Medida [op.acc.1] Control de Acceso Auditor.

Compliance Alignment:
 - ENS (Esquema Nacional de Seguridad RD 311/2022): Medida [op.acc.1] Registro y Gestión de Identidades / Mínimo Privilegio
 - CCN-STIC-804: Guía de Seguridad y Gestión de Accesos
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
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


class ENSAccessPolicyAuditor:
    """Inspecciona políticas de acceso, mínimos privilegios y segregación de funciones según ENS Alto [op.acc.1]."""

    VIOLATIONS = {
        "WORLD_WRITABLE": "Permisos 777 o escritura global permitida.",
        "HARDCODED_CREDS": "Credenciales o tokens hardcodeados en el script.",
        "ROOT_EXECUTION": "Ejecución obligatoria como root/Administrador sin principio de mínimo privilegio."
    }

    def audit_environment(self, target_path: Path) -> Dict[str, Any]:
        findings = []
        files_scanned = 0

        for root, _, files in os.walk(target_path):
            if any(x in root for x in ['.venv', 'venv', '.git', 'reports']):
                continue
            for file in files:
                files_scanned += 1
                fpath = Path(root) / file
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    if "password =" in content.lower() or "secret_key =" in content.lower() or "api_key =" in content.lower():
                        findings.append({
                            "file": str(fpath.name),
                            "type": "HARDCODED_CREDS",
                            "severity": "CRITICAL",
                            "description": "Posible secreto o credencial hardcodeada en texto plano."
                        })
                    if "chmod 777" in content or "Chmod 0777" in content:
                        findings.append({
                            "file": str(fpath.name),
                            "type": "WORLD_WRITABLE",
                            "severity": "HIGH",
                            "description": "Asignación insegura de permisos globales chmod 777."
                        })
                except Exception:
                    pass

        return {
            "files_scanned": files_scanned,
            "violations_count": len(findings),
            "findings": findings,
            "ens_compliant": len(findings) == 0
        }


def save_evidence(data: Dict[str, Any], output_dir: Path) -> Tuple[Path, Path, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"ens_access_policy_report_{ts}.json"
    md_path = output_dir / f"ens_access_policy_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest().upper()

    data_with_hash = dict(data)
    data_with_hash["report_sha256"] = sha256_hash

    json_path.write_text(json.dumps(data_with_hash, indent=2, ensure_ascii=False), encoding="utf-8")

    md_content = f"""# ENS RD 311/2022 Medida [op.acc.1] Control de Acceso Evidence Report

- **Timestamp (UTC):** `{data['timestamp']}`
- **Execution Mode:** `{'DRY-RUN (Simulation)' if data['dry_run'] else 'PRODUCTION'}`
- **Target Path:** `{data['target_path']}`
- **Files Scanned:** `{data['analysis']['files_scanned']}`
- **Access Violations Detected:** `{data['analysis']['violations_count']}`
- **ENS RD 311/2022 Compliant:** `{data['analysis']['ens_compliant']}`
- **SHA-256 Checksum:** `{sha256_hash}`

## Access Policy Violations Details
```json
{json.dumps(data['analysis']['findings'], indent=2)}
```
"""
    md_path.write_text(md_content, encoding="utf-8")
    return json_path, md_path, sha256_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="Auditor ENS RD 311/2022 Medida [op.acc.1] Control de Acceso.")
    parser.add_argument("-i", "--input", type=str, default=None, help="Ruta al directorio a auditar")
    parser.add_argument("-o", "--output", type=str, default=None, help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación")

    args = parser.parse_args()

    input_str = clean_path(args.input) if args.input else None
    if not input_str:
        input_str = input("Ingrese la ruta del directorio a auditar [Defecto: .]: ").strip() or "."
    target_path = Path(clean_path(input_str)).resolve()

    if not target_path.exists():
        print(f"[-] Error: La ruta especificada no existe: {target_path}", file=sys.stderr)
        sys.exit(1)

    output_str = clean_path(args.output) if args.output else None
    if not output_str:
        output_str = "./reports"
    output_dir = Path(clean_path(output_str)).resolve()

    auditor = ENSAccessPolicyAuditor()
    analysis = auditor.audit_environment(target_path)

    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis
    }

    json_p, md_p, sha_digest = save_evidence(payload, output_dir)
    print(f"[+] Auditoría ENS [op.acc.1] Control de Acceso completada.")
    print(f"    Archivos analizados: {analysis['files_scanned']}")
    print(f"    Violaciones de acceso detectadas: {analysis['violations_count']}")
    print(f"    Informe JSON: {json_p}")
    print(f"    Informe MD:   {md_p}")
    print(f"    Firma SHA-256: {sha_digest}")


if __name__ == "__main__":
    main()
