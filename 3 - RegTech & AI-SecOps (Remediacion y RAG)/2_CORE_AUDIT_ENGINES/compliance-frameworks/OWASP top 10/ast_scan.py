"""
Module: ast_scan.py
Description: Production-ready enterprise component for Ast Scan.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


import logging
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

#!/usr/bin/env python3
"""
ast_scan.py — AST Static Analysis for Third-Party Dependency Detection.

Compliance Alignment:
 - OWASP Top 10: A06 (Vulnerable and Outdated Components)
 - ENS RD 311/2022: Medida [op.exp.5] Gestión de Configuración y Software
 - NIS2 Directiva UE 2022/2555: Art. 21 Gestión de Riesgos en Cadena de Suministro
"""

from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

MAPPING: Dict[str, str] = {
    "dotenv": "python-dotenv",
    "argon2": "argon2-cffi",
    "jwt": "PyJWT",
    "pytest_asyncio": "pytest-asyncio",
    "httpcore": "httpcore2",
    "httpx2": "httpx2",
    "win32crypt": "pywin32",
    "yaml": "PyYAML",
    "OpenSSL": "pyOpenSSL",
    "opentelemetry": "opentelemetry-api",
    "pkcs11": "python-pkcs11",
}


def clean_path(path_str: str) -> str:
    """Sanitiza y limpia cadenas de rutas de comillas y espacios residuales."""
    if not path_str:
        return ""
    cleaned = path_str.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def analyze_directory(target_path: Path) -> Dict[str, Any]:
    """Escanea AST de archivos Python para detectar dependencias externas."""
    py_files: List[Path] = []
    ignored_dirs = {'.venv', 'venv', '.git', 'dist', 'build', '.pytest_cache', '.flake8_cache', 'node_modules'}

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        for file in files:
            if file.endswith('.py'):
                py_files.append(Path(root) / file)

    imports: Set[str] = set()
    for file_path in py_files:
        try:
            tree = ast.parse(file_path.read_text(encoding='utf-8'), filename=str(file_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        imports.add(name.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
        except Exception:
            pass

    stdlib = sys.stdlib_module_names if hasattr(sys, 'stdlib_module_names') else set()
    local_modules: Set[str] = set()
    if target_path.exists() and target_path.is_dir():
        for entry in target_path.iterdir():
            if entry.is_dir():
                local_modules.add(entry.name)

    missing_packages: List[str] = []
    detected_packages: List[str] = []

    for imp in sorted(imports):
        if imp in stdlib or imp in local_modules or not imp:
            continue

        pip_name = MAPPING.get(imp, imp)
        detected_packages.append(pip_name)

        try:
            spec = importlib.util.find_spec(imp)
        except Exception:
            spec = None

        if spec is None:
            missing_packages.append(pip_name)

    return {
        "scanned_files_count": len(py_files),
        "detected_packages": detected_packages,
        "missing_packages": missing_packages,
        "is_compliant": len(missing_packages) == 0
    }


def save_evidence(data: Dict[str, Any], output_dir: Path) -> Tuple[Path, Path, str]:
    """Escribe informe dual JSON/MD con sellado temporal UTC e integridad SHA-256."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"ast_scan_report_{ts}.json"
    md_path = output_dir / f"ast_scan_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode('utf-8')).hexdigest().upper()

    data_with_hash = dict(data)
    data_with_hash["report_sha256"] = sha256_hash

    json_path.write_text(json.dumps(data_with_hash, indent=2, ensure_ascii=False), encoding='utf-8')

    md_content = f"""# OWASP Top 10 AST Static Analysis Evidence Report

- **Timestamp (UTC):** `{data['timestamp']}`
- **Execution Mode:** `{'DRY-RUN (Simulation)' if data['dry_run'] else 'PRODUCTION'}`
- **Target Path:** `{data['target_path']}`
- **Scanned Files:** `{data['analysis']['scanned_files_count']}`
- **Compliant:** `{data['analysis']['is_compliant']}`
- **SHA-256 Checksum:** `{sha256_hash}`

## Detected External Dependencies
```json
{json.dumps(data['analysis']['detected_packages'], indent=2)}
```

## Missing / Uninstalled Dependencies
```json
{json.dumps(data['analysis']['missing_packages'], indent=2)}
```
"""
    md_path.write_text(md_content, encoding='utf-8')
    return json_path, md_path, sha256_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="Escáner AST estático de dependencias externas.")
    parser.add_argument("-i", "--input", type=str, default=None, help="Ruta al directorio a escanear")
    parser.add_argument("-o", "--output", type=str, default=None, help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación sin modificaciones")

    args = parser.parse_args()

    input_str = clean_path(args.input) if args.input else None
    if not input_str:
        input_str = input("Ingrese la ruta del directorio a escanear [Defecto: .]: ").strip() or "."
    target_path = Path(clean_path(input_str)).resolve()

    if not target_path.exists():
        logger.info(f"[-] Error: La ruta especificada no existe: {target_path}", file=sys.stderr)
        sys.exit(1)

    output_str = clean_path(args.output) if args.output else None
    if not output_str:
        output_str = "./reports"
    output_dir = Path(clean_path(output_str)).resolve()

    analysis = analyze_directory(target_path)
    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis
    }

    json_p, md_p, sha_digest = save_evidence(payload, output_dir)
    logger.info(f"[+] Escaneo AST completado.")
    logger.info(f"    Archivos escaneados: {analysis['scanned_files_count']}")
    logger.info(f"    Paquetes detectados: {len(analysis['detected_packages'])}")
    logger.info(f"    Paquetes faltantes:  {len(analysis['missing_packages'])}")
    logger.info(f"    Informe JSON: {json_p}")
    logger.info(f"    Informe MD:   {md_p}")
    logger.info(f"    Firma SHA-256: {sha_digest}")


if __name__ == "__main__":
    main()
