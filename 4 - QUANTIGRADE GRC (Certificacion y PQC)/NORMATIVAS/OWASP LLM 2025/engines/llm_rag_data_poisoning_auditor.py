#!/usr/bin/env python3
"""
llm_rag_data_poisoning_auditor.py — OWASP LLM03: RAG Vector Database Data Poisoning Inspector.

Compliance Alignment:
 - OWASP LLM 2025: LLM03 (Training Data Poisoning & Vector Contamination)
 - EU AI Act: Art. 10 Governance & Data Pipeline Quality
 - ENS RD 311/2022: Medida [op.exp.6] Protección del Procesamiento de Datos
"""


from __future__ import annotations

import logging
import os

logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

import argparse
import datetime
import hashlib
import json
import os
import re
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


class RAGPoisoningAuditor:
    """Audita documentos de entrenamiento y corpus de ingesta RAG para detectar datos envenenados o manipulados."""

    SUSPICIOUS_PATTERNS = [
        re.compile(r"ignore\s+previous\s+instructions\s+and\s+output", re.IGNORECASE),
        re.compile(r"ADMIN_BACKDOOR_KEY\s*=\s*['\"]", re.IGNORECASE),
        re.compile(r"override_system_behavior\s*\(\s*\)", re.IGNORECASE),
        re.compile(r"[\u200b-\u200d\ufeff]", re.UNICODE),  # Invisible zero-width unicode injection
        re.compile(r"eval\s*\(\s*base64\.b64decode", re.IGNORECASE),
    ]

    def scan_file(self, file_path: Path) -> list[dict[str, Any]]:
        """Ejecuta la logica de scan_file."""
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            for idx, line in enumerate(lines, 1):
                for pat in self.SUSPICIOUS_PATTERNS:
                    if pat.search(line):
                        findings.append({
                            "line": idx,
                            "type": "VECTOR_POISONING_ATTEMPT",
                            "severity": "HIGH",
                            "snippet": line[:100].strip(),
                            "pattern_matched": pat.pattern
                        })
        except Exception:
            pass
        return findings

    def scan_dataset(self, dataset_path: Path) -> dict[str, Any]:
        """Ejecuta la logica de scan_dataset."""
        all_findings = []
        scanned_count = 0

        for root, _, files in os.walk(dataset_path):
            if any(x in root for x in ['.venv', 'venv', '.git', 'reports']):
                continue
            for file in files:
                if file.endswith(('.json', '.jsonl', '.txt', '.md', '.csv', '.parquet')):
                    fpath = Path(root) / file
                    scanned_count += 1
                    file_findings = self.scan_file(fpath)
                    if file_findings:
                        all_findings.append({
                            "file": str(fpath.relative_to(dataset_path) if fpath.is_relative_to(dataset_path) else fpath),
                            "findings": file_findings
                        })

        return {
            "scanned_files_count": scanned_count,
            "poisoned_files_count": len(all_findings),
            "findings_details": all_findings,
            "is_clean": len(all_findings) == 0
        }


def save_evidence(data: dict[str, Any], output_dir: Path) -> tuple[Path, Path, str]:
    """Ejecuta la logica de save_evidence."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"llm_rag_poisoning_report_{ts}.json"
    md_path = output_dir / f"llm_rag_poisoning_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest().upper()

    data_with_hash = dict(data)
    data_with_hash["report_sha256"] = sha256_hash

    json_path.write_text(json.dumps(data_with_hash, indent=2, ensure_ascii=False), encoding="utf-8")

    md_content = f"""# OWASP LLM03: RAG Data Poisoning Audit Evidence Report

- **Timestamp (UTC):** `{data['timestamp']}`
- **Execution Mode:** `{'DRY-RUN (Simulation)' if data['dry_run'] else 'PRODUCTION'}`
- **Dataset Path:** `{data['target_path']}`
- **Scanned Dataset Files:** `{data['analysis']['scanned_files_count']}`
- **Poisoned Files Detected:** `{data['analysis']['poisoned_files_count']}`
- **SHA-256 Checksum:** `{sha256_hash}`

## Poisoning Detections Details
```json
{json.dumps(data['analysis']['findings_details'], indent=2)}
```
"""
    md_path.write_text(md_content, encoding="utf-8")
    return json_path, md_path, sha256_hash


def main() -> None:
    """Ejecuta la logica de main."""
    parser = argparse.ArgumentParser(description="Auditor de Envenenamiento de Datos RAG OWASP LLM03.")
    parser.add_argument("-i", "--input", type=str, default=None, help="Ruta al directorio de corpus/datos RAG")
    parser.add_argument("-o", "--output", type=str, default=None, help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación sin desinfectar archivos")

    args = parser.parse_args()

    input_str = clean_path(args.input) if args.input else None
    if not input_str:
        input_str = input("Ingrese la ruta del directorio de datos RAG [Defecto: .]: ").strip() or "."
    target_path = Path(clean_path(input_str)).resolve()

    if not target_path.exists():
        logger.error(f"[ERROR] Error: La ruta especificada no existe: {target_path}")
        sys.exit(1)

    output_str = clean_path(args.output) if args.output else None
    if not output_str:
        output_str = "./reports"
    output_dir = Path(clean_path(output_str)).resolve()

    auditor = RAGPoisoningAuditor()
    analysis = auditor.scan_dataset(target_path)

    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis
    }

    json_p, md_p, sha_digest = save_evidence(payload, output_dir)
    logger.info("[+] Inspección OWASP LLM03 RAG Data Poisoning completada.")
    logger.info(f"    Archivos escaneados: {analysis['scanned_files_count']}")
    logger.info(f"    Archivos contaminados: {analysis['poisoned_files_count']}")
    logger.info(f"    Informe JSON: {json_p}")
    logger.info(f"    Informe MD:   {md_p}")
    logger.info(f"    Firma SHA-256: {sha_digest}")


if __name__ == "__main__":
    main()
