#!/usr/bin/env python3
"""
llm_rag_poisoning_auditor.py — CTEM Validation: RAG Vector Corpus & Prompt Injection Inspector.
Aligns with:
 - OWASP LLM Top 10 (2025): LLM03 (Training Data Poisoning) & LLM01 (Prompt Injection)
 - EU AI Act: Art. 10 Governance & Data Pipeline Quality
 - ENS RD 311/2022: Medida [op.exp.6] Protección del Procesamiento de Datos
"""
from __future__ import annotations

import datetime
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.RAGPoisoning")


class LLMRAGPoisoningAuditor:
    """Scans training documents, chunks, and RAG knowledge corpus for hidden poison and backdoors."""

    SUSPICIOUS_PATTERNS = [
        (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "PROMPT_INJECTION_DIRECT", "CRITICAL"),
        (re.compile(r"ADMIN_BACKDOOR_KEY\s*=\s*['\"]", re.IGNORECASE), "BACKDOOR_KEY_EMBEDDED", "CRITICAL"),
        (re.compile(r"override_system_behavior\s*\(\s*\)", re.IGNORECASE), "SYSTEM_BEHAVIOR_OVERRIDE", "CRITICAL"),
        (re.compile(r"[\u200b-\u200d\ufeff]", re.UNICODE), "ZERO_WIDTH_INVISIBLE_INJECTION", "HIGH"),
        (re.compile(r"eval\s*\(\s*base64\.b64decode", re.IGNORECASE), "OBFUSCATED_CODE_EXECUTION", "CRITICAL"),
        (re.compile(r"system_prompt_leak\s*:\s*true", re.IGNORECASE), "PROMPT_LEAK_FLAG", "HIGH"),
    ]

    def scan_text(self, text: str, source_name: str = "memory_buffer") -> list[dict[str, Any]]:
        findings = []
        lines = text.splitlines()

        for idx, line in enumerate(lines, 1):
            for regex, issue_type, severity in self.SUSPICIOUS_PATTERNS:
                if regex.search(line):
                    findings.append({
                        "source": source_name,
                        "line": idx,
                        "type": issue_type,
                        "severity": severity,
                        "snippet": line.strip()[:120],
                        "hash": hashlib.sha256(line.encode("utf-8", errors="ignore")).hexdigest()[:16]
                    })
        return findings

    def scan_file(self, file_path: Path) -> list[dict[str, Any]]:
        p = Path(file_path)
        if not p.exists():
            return []
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            return self.scan_text(content, source_name=str(p.name))
        except Exception as e:
            logger.debug("Error reading %s: %s", p, e)
            return []

    def scan_corpus_directory(self, directory: Path) -> dict[str, Any]:
        p = Path(directory)
        findings: list[dict[str, Any]] = []
        files_scanned = 0

        if not p.exists():
            return {
                "target": str(directory),
                "error": "Directory not found",
                "files_scanned": 0,
                "findings": []
            }

        for root, _, files in os.walk(p):
            if any(x in root for x in [".git", "node_modules", ".venv", "__pycache__"]):
                continue
            for file in files:
                if file.endswith((".txt", ".md", ".json", ".csv", ".parquet", ".pdf.txt")):
                    fpath = Path(root) / file
                    files_scanned += 1
                    file_findings = self.scan_file(fpath)
                    findings.extend(file_findings)

        crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")

        return {
            "target": str(p),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "files_scanned": files_scanned,
            "total_poison_findings": len(findings),
            "critical_findings": crit_count,
            "high_findings": high_count,
            "status": "POISON_DETECTED" if len(findings) > 0 else "CLEAN",
            "findings": findings
        }

