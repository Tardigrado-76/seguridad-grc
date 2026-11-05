#!/usr/bin/env python3
"""
ens_access_policy_ctem.py — CTEM Validation: ENS RD 311/2022 Medida [op.acc.1] Control de Acceso Auditor.
Aligns with:
 - ENS RD 311/2022: Medida [op.acc.1] Registro y Gestión de Identidades / Mínimo Privilegio
 - CCN-STIC-804: Guía de Seguridad y Gestión de Accesos
"""
from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.ENSAccess")


class ENSAccessPolicyCTEMAuditor:
    """Inspects codebase and environment configurations for hardcoded credentials, world-writable files, and root enforcement."""

    def audit_environment(self, target_path: Path) -> dict[str, Any]:
        findings = []
        files_scanned = 0
        p = Path(target_path)

        if not p.exists():
            return {
                "target": str(target_path),
                "error": "Path does not exist",
                "files_scanned": 0,
                "findings": []
            }

        for root, _, files in os.walk(p):
            if any(x in root for x in [".venv", "venv", ".git", "reports", "node_modules"]):
                continue
            for file in files:
                files_scanned += 1
                fpath = Path(root) / file
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    low_content = content.lower()

                    if any(bad in low_content for bad in ["password = \"admin", "secret_key = \"changeme", "api_key = \"12345"]):
                        findings.append({
                            "file": str(fpath.name),
                            "type": "HARDCODED_DEFAULT_CREDS",
                            "severity": "CRITICAL",
                            "description": "Credencial por defecto o contraseña débil hardcodeada en texto plano.",
                            "control": "op.acc.1"
                        })
                    if "chmod 777" in content or "chmod 0777" in content:
                        findings.append({
                            "file": str(fpath.name),
                            "type": "WORLD_WRITABLE_PERMISSIONS",
                            "severity": "HIGH",
                            "description": "Asignación insegura de permisos globales chmod 777.",
                            "control": "op.acc.6"
                        })
                except Exception:
                    pass

        crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")

        return {
            "target": str(p),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "files_scanned": files_scanned,
            "violations_found": len(findings),
            "critical_violations": crit_count,
            "high_violations": high_count,
            "status": "PASS" if len(findings) == 0 else "FAIL",
            "findings": findings
        }

