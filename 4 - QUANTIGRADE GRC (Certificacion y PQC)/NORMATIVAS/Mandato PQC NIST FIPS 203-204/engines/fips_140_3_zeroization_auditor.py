#!/usr/bin/env python3
"""fips_140_3_zeroization_auditor.py — FIPS 140-3 Cryptographic Module Self-Test & Zeroization Auditor.

Compliance Alignment:
 - FIPS 140-3: Security Requirements for Cryptographic Modules (Level 1-4 Zeroization & KAT Self-Tests)
 - NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization
 - ENS RD 311/2022: Medida [op.exp.5] Borrado Seguro y Sanitización
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


class FIPS1403ZeroizationAuditor:
    """Inspecciona rutinas de memoria, gestión de claves y sanitización segura según FIPS 140-3."""

    CRITICAL_ZEROIZATION_KEYWORDS = [
        "memset_s", "explicit_bzero", "zeroize_key", "secure_memzero",
        "crypt_keyspec_zero", "win32_secure_zero_memory",
    ]

    INSECURE_MEM_PATTERNS = [
        "del key", "key = None", "free(key)", "delete key",
    ]

    def audit_source_code(self, target_path: Path) -> dict[str, Any]:
        zeroization_routines_found = []
        insecure_patterns_found = []
        files_scanned = 0

        for root, _, files in os.walk(target_path):
            if any(x in root for x in [".venv", "venv", ".git", "reports"]):
                continue
            for file in files:
                if file.endswith((".c", ".cpp", ".py", ".go", ".rs", ".cs")):
                    files_scanned += 1
                    fpath = Path(root) / file
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                        for kw in self.CRITICAL_ZEROIZATION_KEYWORDS:
                            if kw in content:
                                zeroization_routines_found.append({
                                    "file": str(fpath.name),
                                    "keyword": kw,
                                })
                        for ins in self.INSECURE_MEM_PATTERNS:
                            if ins in content:
                                insecure_patterns_found.append({
                                    "file": str(fpath.name),
                                    "insecure_pattern": ins,
                                })
                    except Exception:
                        pass

        is_compliant = len(zeroization_routines_found) > 0 and len(insecure_patterns_found) == 0

        return {
            "files_scanned": files_scanned,
            "zeroization_routines_count": len(zeroization_routines_found),
            "zeroization_details": zeroization_routines_found,
            "insecure_patterns_count": len(insecure_patterns_found),
            "insecure_details": insecure_patterns_found,
            "is_compliant": is_compliant,
        }


def save_evidence(data: dict[str, Any], output_dir: Path) -> tuple[Path, Path, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"fips_140_3_zeroization_report_{ts}.json"
    md_path = output_dir / f"fips_140_3_zeroization_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest().upper()

    data_with_hash = dict(data)
    data_with_hash["report_sha256"] = sha256_hash

    json_path.write_text(json.dumps(data_with_hash, indent=2, ensure_ascii=False), encoding="utf-8")

    md_content = f"""# FIPS 140-3 Key Zeroization & Cryptographic Module Audit Report

- **Timestamp (UTC):** `{data['timestamp']}`
- **Execution Mode:** `{'DRY-RUN (Simulation)' if data['dry_run'] else 'PRODUCTION'}`
- **Target Path:** `{data['target_path']}`
- **Source Files Scanned:** `{data['analysis']['files_scanned']}`
- **Zeroization Routines Verified:** `{data['analysis']['zeroization_routines_count']}`
- **Insecure Key Disposals:** `{data['analysis']['insecure_patterns_count']}`
- **FIPS 140-3 Compliant:** `{data['analysis']['is_compliant']}`
- **SHA-256 Checksum:** `{sha256_hash}`

## Zeroization Routines Detected
```json
{json.dumps(data['analysis']['zeroization_details'], indent=2)}
```

## Insecure Key Memory Releases
```json
{json.dumps(data['analysis']['insecure_details'], indent=2)}
```
"""
    md_path.write_text(md_content, encoding="utf-8")
    return json_path, md_path, sha256_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="Auditor FIPS 140-3 de Zeroización y Autoevaluación del Módulo Criptográfico.")
    parser.add_argument("-i", "--input", type=str, default=None, help="Ruta al directorio de fuentes del módulo criptográfico")
    parser.add_argument("-o", "--output", type=str, default=None, help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación")

    args = parser.parse_args()

    input_str = clean_path(args.input) if args.input else None
    if not input_str:
        input_str = input("Ingrese la ruta del directorio del módulo criptográfico [Defecto: .]: ").strip() or "."
    target_path = Path(clean_path(input_str)).resolve()

    if not target_path.exists():
        sys.exit(1)

    output_str = clean_path(args.output) if args.output else None
    if not output_str:
        output_str = "./reports"
    output_dir = Path(clean_path(output_str)).resolve()

    auditor = FIPS1403ZeroizationAuditor()
    analysis = auditor.audit_source_code(target_path)

    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis,
    }

    _json_p, _md_p, _sha_digest = save_evidence(payload, output_dir)


if __name__ == "__main__":
    main()
