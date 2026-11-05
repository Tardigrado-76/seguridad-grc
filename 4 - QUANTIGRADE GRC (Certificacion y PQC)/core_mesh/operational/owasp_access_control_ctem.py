#!/usr/bin/env python3
"""
owasp_access_control_ctem.py — CTEM Validation: OWASP Top 10 A01 Broken Access Control & IDOR Auditor.
Aligns with:
 - OWASP Top 10 2021/2025: A01 Broken Access Control
 - ENS RD 311/2022: Medida [op.acc.1] Control de Acceso
 - NIS2 Directiva UE 2022/2555: Art. 21 Gestión de Accesos
"""
from __future__ import annotations

import datetime
import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.OWASP")


class OWASPAccessControlAuditor:
    """Audits source code repositories for Broken Access Control, IDOR, BOLA and missing auth guards."""

    UNPROTECTED_ENDPOINT_PATTERNS = [
        re.compile(r"@app\.(get|post|put|delete|patch)\(['\"]/api/v\d+/(user|account|order|file|document)/<int:id>['\"]\)", re.IGNORECASE),
        re.compile(r"def\s+get_(user|account|order|file)_data\s*\(\s*(user_id|account_id|id)\s*:\s*int\s*\)", re.IGNORECASE),
        re.compile(r"SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+id\s*=\s*['\"]?\s*\+\s*req", re.IGNORECASE),
        re.compile(r"request\.args\.get\(['\"]id['\"]\).*cursor\.execute", re.IGNORECASE),
    ]

    MISSING_AUTH_DECORATOR_PATTERNS = [
        re.compile(r"def\s+admin_\w+\s*\(", re.IGNORECASE),
        re.compile(r"def\s+delete_(user|record|tenant|database)\s*\(", re.IGNORECASE),
        re.compile(r"def\s+purge_\w+\s*\(", re.IGNORECASE),
    ]

    def scan_file(self, file_path: Path) -> list[dict[str, Any]]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            for idx, line in enumerate(lines, 1):
                # Check for IDOR / BOLA risks
                for pat in self.UNPROTECTED_ENDPOINT_PATTERNS:
                    if pat.search(line):
                        findings.append({
                            "line": idx,
                            "type": "IDOR_BOLA_RISK",
                            "severity": "HIGH",
                            "snippet": line.strip()[:140],
                            "recommendation": "Verificar pertenencia del recurso al usuario autenticado (ABAC/context)."
                        })
                # Check for unauthenticated administrative endpoints
                for pat in self.MISSING_AUTH_DECORATOR_PATTERNS:
                    if pat.search(line) and not any(
                        marker in content
                        for marker in ["@login_required", "@requires_role", "@require_abac", "Depends(", "auth_guard"]
                    ):
                        findings.append({
                            "line": idx,
                            "type": "MISSING_AUTHORIZATION_DECORATOR",
                            "severity": "CRITICAL",
                            "snippet": line.strip()[:140],
                            "recommendation": "Añadir decorador explícito de control de acceso y verificación RBAC/ABAC."
                        })
        except Exception as e:
            logger.debug("Skip file %s: %s", file_path, e)
        return findings

    def scan_directory(self, target_path: Path) -> dict[str, Any]:
        all_findings: list[dict[str, Any]] = []
        files_scanned = 0
        p = Path(target_path)

        if not p.exists():
            return {
                "target": str(target_path),
                "error": f"Directorio no encontrado: {target_path}",
                "files_scanned": 0,
                "findings": []
            }

        for root, _, files in os.walk(p):
            if any(x in root for x in [".venv", "venv", ".git", "node_modules", "reports", "__pycache__"]):
                continue
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx")):
                    fpath = Path(root) / file
                    files_scanned += 1
                    file_findings = self.scan_file(fpath)
                    if file_findings:
                        all_findings.append({
                            "file": str(fpath.relative_to(p)),
                            "violations_count": len(file_findings),
                            "findings": file_findings
                        })

        crit_count = sum(sum(1 for f in item["findings"] if f["severity"] == "CRITICAL") for item in all_findings)
        high_count = sum(sum(1 for f in item["findings"] if f["severity"] == "HIGH") for item in all_findings)

        return {
            "target": str(p),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "files_scanned": files_scanned,
            "vulnerable_files_count": len(all_findings),
            "critical_violations": crit_count,
            "high_violations": high_count,
            "status": "PASS" if crit_count == 0 and high_count == 0 else "FAIL",
            "results": all_findings
        }

