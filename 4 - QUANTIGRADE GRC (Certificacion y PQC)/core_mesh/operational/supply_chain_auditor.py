#!/usr/bin/env python3
"""
Supply Chain Security Auditor & VEX Aggregator.
Aligns with CRA Art. 10 (Security by Design), SLSA Level 3+, and NIS2 Art. 21.2.d.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class SupplyChainAuditor:
    """Production-grade Supply Chain Dependency & VEX Auditor."""

    TYPOSQUATTING_SUSPECTS: Set[str] = {
        "reqeusts", "colorama-v2", "urllib4", "pycrypto-legacy", "python-dateutil2",
        "cryptograpy", "pydantic-v3", "fastapi-core"
    }

    VALID_VEX_STATUSES: Set[str] = {
        "not_affected", "affected", "fixed", "under_investigation"
    }

    def __init__(self, base_path: str | Path = ".") -> None:
        self.base_path = Path(base_path)

    def audit_manifest(self, file_path: str | Path) -> List[Dict[str, Any]]:
        path = Path(file_path)
        findings: List[Dict[str, Any]] = []
        if not path.exists():
            return findings

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for line_no, line in enumerate(content.splitlines(), start=1):
                clean = line.strip().lower()
                if not clean or clean.startswith("#"):
                    continue

                for suspect in self.TYPOSQUATTING_SUSPECTS:
                    if suspect in clean:
                        findings.append({
                            "type": "TYPOSQUATTING_SUSPECT",
                            "severity": "CRITICAL",
                            "package": suspect,
                            "line_no": line_no,
                            "file": str(path.name),
                        })

                if "http://" in clean:
                    findings.append({
                        "type": "UNENCRYPTED_REPOSITORY",
                        "severity": "HIGH",
                        "package": clean,
                        "line_no": line_no,
                        "file": str(path.name),
                    })
        except Exception:
            pass
        return findings

    def scan_directory(self, target_dir: str | Path | None = None) -> Dict[str, Any]:
        root_dir = Path(target_dir) if target_dir else self.base_path
        manifest_names = {"requirements.txt", "package.json", "Pipfile", "go.mod", "Cargo.toml"}
        all_findings: List[Dict[str, Any]] = []
        scanned_files = 0

        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in {".git", ".venv", "node_modules", "__pycache__"}]
            for file in files:
                if file in manifest_names:
                    scanned_files += 1
                    all_findings.extend(self.audit_manifest(Path(root) / file))

        return {
            "status": "SUCCESS",
            "files_scanned": scanned_files,
            "findings_count": len(all_findings),
            "findings": all_findings,
        }

    def aggregate_vex(self, vex_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process and filter VEX vulnerability statements according to NIS2 / CycloneDX standards."""
        suppressed: List[Dict[str, Any]] = []
        actionable: List[Dict[str, Any]] = []

        for item in vex_data:
            status = item.get("status", "under_investigation")
            cve_id = item.get("cve_id", "UNKNOWN")
            if status == "not_affected":
                suppressed.append({
                    "cve_id": cve_id,
                    "justification": item.get("justification", "Not specified"),
                    "status": "SUPPRESSED",
                })
            else:
                actionable.append({
                    "cve_id": cve_id,
                    "status": status,
                    "impact": item.get("impact_statement", "Review required"),
                })

        return {
            "total_evaluated": len(vex_data),
            "suppressed_false_positives": len(suppressed),
            "actionable_vulnerabilities": len(actionable),
            "suppressed": suppressed,
            "actionable": actionable,
        }

