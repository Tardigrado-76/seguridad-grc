"""Quantigrade GCR - ISO 27001:2022 & SOC 2 Compliance Mapping Engine.

Transposes technical audit findings (from DORA, NIS2, ENS, CTEM, OWASP)
into certified external audit frameworks:
- ISO/IEC 27001:2022 Annex A controls
- AICPA SOC 2 Trust Services Criteria (Security, Availability, Confidentiality)
100% Native Python stdlib with embedded mapping tables.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Embedded Cross-Normative Mapping Catalog
TAXONOMY_MAP = {
    # Access Control / IAM
    "access_control": {
        "iso_controls": [
            {"id": "A.5.15", "title": "Access control", "domain": "Organizational"},
            {"id": "A.8.2", "title": "Privileged access rights", "domain": "Technological"},
            {"id": "A.8.5", "title": "Secure authentication", "domain": "Technological"},
        ],
        "soc2_criteria": [
            {"id": "CC6.1", "principle": "Security", "description": "Logical access security software and infrastructure"},
            {"id": "CC6.2", "principle": "Security", "description": "User registration and credential management"},
            {"id": "CC6.3", "principle": "Security", "description": "Role-based access authorization"},
        ],
    },
    # Vulnerability & Patch Management
    "vulnerability_management": {
        "iso_controls": [
            {"id": "A.8.8", "title": "Management of technical vulnerabilities", "domain": "Technological"},
            {"id": "A.8.7", "title": "Protection against malware", "domain": "Technological"},
        ],
        "soc2_criteria": [
            {"id": "CC7.1", "principle": "Security", "description": "Vulnerability scanning and remediation"},
            {"id": "CC7.2", "principle": "Security", "description": "Real-time threat monitoring and anomaly detection"},
        ],
    },
    # Cryptography & Vault Integrity
    "cryptography": {
        "iso_controls": [
            {"id": "A.8.24", "title": "Use of cryptography", "domain": "Technological"},
            {"id": "A.5.33", "title": "Protection of records", "domain": "Organizational"},
        ],
        "soc2_criteria": [
            {"id": "CC6.6", "principle": "Security", "description": "Data encryption in transit and at rest"},
            {"id": "C1.1", "principle": "Confidentiality", "description": "Confidentiality of protected assets"},
        ],
    },
    # Logging, Audit & Monitoring
    "logging_monitoring": {
        "iso_controls": [
            {"id": "A.8.15", "title": "Logging", "domain": "Technological"},
            {"id": "A.8.16", "title": "Monitoring activities", "domain": "Technological"},
        ],
        "soc2_criteria": [
            {"id": "CC7.2", "principle": "Security", "description": "Security incident detection and event logging"},
            {"id": "CC7.3", "principle": "Security", "description": "Incident evaluation and response triage"},
        ],
    },
    # Supply Chain & Third-Party
    "supply_chain": {
        "iso_controls": [
            {"id": "A.5.19", "title": "Information security in supplier relationships", "domain": "Organizational"},
            {"id": "A.5.21", "title": "Managing information security in ICT supply chain", "domain": "Organizational"},
        ],
        "soc2_criteria": [
            {"id": "CC9.2", "principle": "Security", "description": "Vendor and third-party risk assessment"},
        ],
    },
    # Business Continuity & Resilience
    "resilience": {
        "iso_controls": [
            {"id": "A.8.13", "title": "Information backup", "domain": "Technological"},
            {"id": "A.8.14", "title": "Redundancy of information processing facilities", "domain": "Technological"},
        ],
        "soc2_criteria": [
            {"id": "A1.1", "principle": "Availability", "description": "Capacity planning and environmental failover"},
            {"id": "A1.2", "principle": "Availability", "description": "System backup and recovery procedures"},
        ],
    },
    # Secure Coding & AI Guardrails
    "secure_coding": {
        "iso_controls": [
            {"id": "A.8.25", "title": "Secure development life cycle", "domain": "Technological"},
            {"id": "A.8.28", "title": "Secure coding", "domain": "Technological"},
        ],
        "soc2_criteria": [
            {"id": "CC8.1", "principle": "Security", "description": "Change management and secure development lifecycle"},
        ],
    },
}


class ISOSOCComplianceMapper:
    """Engine for mapping operational and regulatory findings to ISO 27001 and SOC 2."""

    def __init__(self) -> None:
        self.catalog = TAXONOMY_MAP

    def _infer_category(self, finding: Dict[str, Any]) -> str:
        """Infer taxonomic category from finding metadata, tags, or rule ID."""
        text = " ".join([
            str(finding.get("rule_id", "")),
            str(finding.get("category", "")),
            str(finding.get("title", "")),
            str(finding.get("description", "")),
            str(finding.get("framework", "")),
        ]).lower()

        if any(w in text for w in ["access", "iam", "auth", "mfa", "privilege", "idor", "bola", "op.acc"]):
            return "access_control"
        if any(w in text for w in ["vuln", "patch", "cve", "stig", "cwe", "op.vul"]):
            return "vulnerability_management"
        if any(w in text for w in ["crypto", "cipher", "vault", "pqc", "cert", "hash", "fips"]):
            return "cryptography"
        if any(w in text for w in ["log", "audit", "trace", "heartbeat", "telemetry", "op.exp.8"]):
            return "logging_monitoring"
        if any(w in text for w in ["supply", "tprm", "sbom", "vendor", "slsa"]):
            return "supply_chain"
        if any(w in text for w in ["resilience", "rto", "rpo", "airgap", "backup", "chaos"]):
            return "resilience"
        if any(w in text for w in ["code", "ast", "prompt", "llm", "injection", "guardrail"]):
            return "secure_coding"
        return "vulnerability_management"

    def map_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Map a single finding to ISO 27001 Annex A controls and SOC 2 TSC."""
        cat = self._infer_category(finding)
        mapping_data = self.catalog.get(cat, self.catalog["vulnerability_management"])

        mapped = dict(finding)
        mapped["category_inferred"] = cat
        mapped["iso_27001_controls"] = mapping_data["iso_controls"]
        mapped["soc_2_criteria"] = mapping_data["soc2_criteria"]
        mapped["mapped_at"] = datetime.now(timezone.utc).isoformat()
        return mapped

    def bulk_map(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map a list of findings in bulk."""
        return [self.map_finding(f) for f in findings]

    def export_report(self, mappings: List[Dict[str, Any]], fmt: str = "json") -> str:
        """Export mapped findings report to JSON or Markdown table."""
        if fmt == "json":
            return json.dumps(mappings, indent=2, ensure_ascii=False)

        # Markdown format
        lines = [
            "# Informe de Transposición Regulatoria: ISO 27001:2022 & SOC 2",
            f"Generado: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "| ID Hallazgo | Framework Origen | Severidad | Controles ISO 27001:2022 | Criterios SOC 2 |",
            "|:---|:---|:---|:---|:---|",
        ]
        for m in mappings:
            fid = m.get("id", m.get("rule_id", "FND-001"))
            fw = m.get("framework", "QG_CORE")
            sev = m.get("severity", "MEDIUM")
            iso_str = ", ".join([c["id"] for c in m.get("iso_27001_controls", [])])
            soc_str = ", ".join([c["id"] for c in m.get("soc_2_criteria", [])])
            lines.append(f"| `{fid}` | {fw} | **{sev}** | {iso_str} | {soc_str} |")

        return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Quantigrade GCR - ISO 27001 & SOC 2 Compliance Mapper CLI")
    parser.add_argument("-i", "--input", help="Path to JSON file with findings")
    parser.add_argument("-o", "--output", help="Path to write mapped report")
    parser.add_argument("-f", "--format", choices=["json", "md"], default="json", help="Output format")

    args = parser.parse_args()
    mapper = ISOSOCComplianceMapper()

    if args.input and Path(args.input).exists():
        raw_text = Path(args.input).read_text(encoding="utf-8")
        findings = json.loads(raw_text)
        if isinstance(findings, dict):
            findings = [findings]
    else:
        # Sample findings demonstration
        findings = [
            {
                "id": "FND-DORA-01",
                "framework": "DORA",
                "title": "MFA no forzado en acceso administrativo",
                "severity": "HIGH",
            },
            {
                "id": "FND-ENS-02",
                "framework": "ENS",
                "title": "Vulnerabilidad crítica sin parche en host",
                "severity": "CRITICAL",
            },
            {
                "id": "FND-AI-03",
                "framework": "EU_AI_ACT",
                "title": "Inyección de prompt detectada en endpoint LLM",
                "severity": "HIGH",
            },
        ]

    mapped = mapper.bulk_map(findings)
    rep = mapper.export_report(mapped, fmt=args.format)

    if args.output:
        Path(args.output).write_text(rep, encoding="utf-8")
        print(f"[+] Reporte exportado exitosamente a: {args.output}")
    else:
        print(rep)


if __name__ == "__main__":
    main()

