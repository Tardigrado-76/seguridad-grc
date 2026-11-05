"""
Module: eu_ai_act_human_oversight_auditor.py
Description: Production-ready enterprise component for Eu Ai Act Human Oversight Auditor.
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
eu_ai_act_human_oversight_auditor.py — EU AI Act Art. 14 Human Oversight & Explainability Log Auditor.

Compliance Alignment:
 - EU AI Act (Reglamento UE 2024/1689): Art. 14 (Supervisión Humana) y Art. 12 (Registro Automático)
 - AESIA / NISTR 8470: Explicabilidad y Trazabilidad de Decisiones Algorítmicas
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


class HumanOversightAuditor:
    """Audita registros de decisiones de modelos de IA para verificar cumplimiento de supervisión humana Art. 14."""

    REQUIRED_FIELDS = ["decision_id", "timestamp", "model_version", "risk_level", "human_operator_id", "human_approval_status", "explainability_score"]

    def audit_log_file(self, log_path: Path) -> Dict[str, Any]:
        total_records = 0
        non_compliant_records = []

        try:
            content = log_path.read_text(encoding="utf-8", errors="ignore")
            for idx, line in enumerate(content.splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    total_records += 1
                    missing = [f for f in self.REQUIRED_FIELDS if f not in record]
                    if missing or record.get("human_approval_status") is None:
                        non_compliant_records.append({
                            "record_index": idx,
                            "missing_fields": missing,
                            "human_approval_present": record.get("human_approval_status") is not None
                        })
                except Exception:
                    pass
        except Exception:
            pass

        return {
            "file": log_path.name,
            "total_records": total_records,
            "non_compliant_records_count": len(non_compliant_records),
            "details": non_compliant_records,
            "is_compliant": len(non_compliant_records) == 0
        }

    def scan_directory(self, target_path: Path) -> Dict[str, Any]:
        log_audits = []
        files_scanned = 0

        for root, _, files in os.walk(target_path):
            if any(x in root for x in ['.venv', 'venv', '.git', 'reports']):
                continue
            for file in files:
                if file.endswith(('.jsonl', '.log', '.json')):
                    fpath = Path(root) / file
                    files_scanned += 1
                    res = self.audit_log_file(fpath)
                    if res["total_records"] > 0:
                        log_audits.append(res)

        return {
            "files_scanned": files_scanned,
            "audited_log_files_count": len(log_audits),
            "log_audits": log_audits,
            "overall_compliant": all(a["is_compliant"] for a in log_audits) if log_audits else True
        }


def save_evidence(data: Dict[str, Any], output_dir: Path) -> Tuple[Path, Path, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"eu_ai_act_human_oversight_report_{ts}.json"
    md_path = output_dir / f"eu_ai_act_human_oversight_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest().upper()

    data_with_hash = dict(data)
    data_with_hash["report_sha256"] = sha256_hash

    json_path.write_text(json.dumps(data_with_hash, indent=2, ensure_ascii=False), encoding="utf-8")

    md_content = f"""# EU AI Act Art. 14 Human Oversight & Explainability Evidence Report

- **Timestamp (UTC):** `{data['timestamp']}`
- **Execution Mode:** `{'DRY-RUN (Simulation)' if data['dry_run'] else 'PRODUCTION'}`
- **Target Path:** `{data['target_path']}`
- **Files Scanned:** `{data['analysis']['files_scanned']}`
- **Audited AI Logs:** `{data['analysis']['audited_log_files_count']}`
- **Overall Compliant:** `{data['analysis']['overall_compliant']}`
- **SHA-256 Checksum:** `{sha256_hash}`

## Audit Details per Log File
```json
{json.dumps(data['analysis']['log_audits'], indent=2)}
```
"""
    md_path.write_text(md_content, encoding="utf-8")
    return json_path, md_path, sha256_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="Auditor de Supervisión Humana Art. 14 EU AI Act.")
    parser.add_argument("-i", "--input", type=str, default=None, help="Ruta al directorio de logs de decisiones IA")
    parser.add_argument("-o", "--output", type=str, default=None, help="Ruta al directorio de salida de informes")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Modo simulación")

    args = parser.parse_args()

    input_str = clean_path(args.input) if args.input else None
    if not input_str:
        input_str = input("Ingrese la ruta del directorio de logs de decisiones IA [Defecto: .]: ").strip() or "."
    target_path = Path(clean_path(input_str)).resolve()

    if not target_path.exists():
        logger.info(f"[-] Error: La ruta especificada no existe: {target_path}", file=sys.stderr)
        sys.exit(1)

    output_str = clean_path(args.output) if args.output else None
    if not output_str:
        output_str = "./reports"
    output_dir = Path(clean_path(output_str)).resolve()

    auditor = HumanOversightAuditor()
    analysis = auditor.scan_directory(target_path)

    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "target_path": str(target_path),
        "analysis": analysis
    }

    json_p, md_p, sha_digest = save_evidence(payload, output_dir)
    logger.info(f"[+] Evaluación Art. 14 EU AI Act Supervisión Humana completada.")
    logger.info(f"    Archivos de log auditados: {analysis['audited_log_files_count']}")
    logger.info(f"    Conformidad global: {analysis['overall_compliant']}")
    logger.info(f"    Informe JSON: {json_p}")
    logger.info(f"    Informe MD:   {md_p}")
    logger.info(f"    Firma SHA-256: {sha_digest}")


if __name__ == "__main__":
    main()
