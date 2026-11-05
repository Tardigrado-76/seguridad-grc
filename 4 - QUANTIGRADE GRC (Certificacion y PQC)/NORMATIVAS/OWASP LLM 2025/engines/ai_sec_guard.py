#!/usr/bin/env python3
"""ai_sec_guard.py — EU AI Act & OWASP LLM Inference Safety & Governance Gateway.

Compliance Alignment:
 - EU AI Act: Art. 15 (Cybersecurity, Accuracy & Robustness)
 - OWASP LLM: LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM09 (Overreliance & Bias)
"""

import argparse
import datetime
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any


class AISecurityGuard:
    """Production-grade AI Gateway for Ingress/Egress Inspection, PII Redaction,.

    Prompt Injection Defense, and Bias Audit under EU AI Act & OWASP LLM.
    """

    # Heuristic patterns for Prompt Injection and Jailbreak attempts
    INJECTION_PATTERNS: list[re.Pattern] = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+prior\s+system\s+prompts?", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+in\s+DAN\s+mode", re.IGNORECASE),
        re.compile(r"do\s+anything\s+now", re.IGNORECASE),
        re.compile(r"override\s+system\s+rules?", re.IGNORECASE),
        re.compile(r"bypass\s+safety\s+filters?", re.IGNORECASE),
        re.compile(r"act\s+as\s+an\s+unrestricted\s+AI", re.IGNORECASE),
        re.compile(r"\[SYSTEM\s*:\s*OVERRIDE\]", re.IGNORECASE),
        re.compile(r"<\|im_start\|>\s*system", re.IGNORECASE),
    ]

    # Optimized PII Regex Patterns
    PII_PATTERNS: dict[str, re.Pattern] = {
        "DNI_NIF": re.compile(r"\b\d{8}[A-HJ-NP-TV-Z]\b", re.IGNORECASE),
        "NIE": re.compile(r"\b[XYZ]\d{7}[A-Z]\b", re.IGNORECASE),
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "IBAN": re.compile(r"\bES\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}\b", re.IGNORECASE),
        "CREDIT_CARD": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
        "IPV4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    }

    # Bias and Overreliance heuristic markers
    BIAS_PATTERNS: list[re.Pattern] = [
        re.compile(r"\b(all|every)\s+(men|women|foreigners|immigrants|ethnicities)\s+are\b", re.IGNORECASE),
        re.compile(r"\b(obviously|unquestionably)\s+(inferior|superior)\b", re.IGNORECASE),
        re.compile(r"\babsolute\s+truth\s+without\s+verification\b", re.IGNORECASE),
    ]

    def __init__(self, mode: str = "enforce", salt: str = "EU_AI_ACT_SECRET_SALT_2026") -> None:
        if mode not in ("enforce", "audit"):
            msg = "Mode must be 'enforce' or 'audit'"
            raise ValueError(msg)
        self.mode: str = mode
        self.salt: bytes = salt.encode("utf-8")

    def hash_pii(self, value: str) -> str:
        """Deterministically hashes PII value using HMAC-SHA256."""
        return "[REDACTED_PII:" + hmac.new(self.salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:12] + "]"

    def scan_prompt_injection(self, text: str) -> tuple[bool, list[str]]:
        """Scans input text for known prompt injection / jailbreak patterns."""
        matches: list[str] = []
        for pattern in self.INJECTION_PATTERNS:
            found = pattern.findall(text)
            if found:
                matches.extend([f"Pattern matched: {pattern.pattern}"])
        return len(matches) > 0, matches

    def redact_pii(self, text: str) -> tuple[str, list[dict[str, str]]]:
        """Scans and redacts PII elements in text using salted HMAC hashing."""
        redacted_text = text
        detections: list[dict[str, str]] = []

        for pii_type, pattern in self.PII_PATTERNS.items():
            for match in pattern.finditer(text):
                val = match.group(0)
                replacement = self.hash_pii(val)
                redacted_text = redacted_text.replace(val, replacement)
                detections.append({"type": pii_type, "redacted_hash": replacement})

        return redacted_text, detections

    def audit_bias(self, text: str) -> tuple[float, list[str]]:
        """Audits text for bias and overreliance indicators, returning a risk score [0.0 - 1.0]."""
        findings: list[str] = []
        score = 0.0
        for pattern in self.BIAS_PATTERNS:
            if pattern.search(text):
                findings.append(f"Bias indicator matched: {pattern.pattern}")
                score += 0.35
        score = min(1.0, score)
        return score, findings

    def inspect(self, input_text: str) -> dict[str, Any]:
        """Performs full inspection pipeline on input text."""
        is_injection, injection_flags = self.scan_prompt_injection(input_text)
        sanitized_text, pii_detections = self.redact_pii(input_text)
        bias_score, bias_findings = self.audit_bias(input_text)

        is_safe = not is_injection and (self.mode == "audit" or len(pii_detections) == 0)
        risk_score = round(min(1.0, (0.6 if is_injection else 0.0) + (len(pii_detections) * 0.1) + bias_score), 2)

        return {
            "is_safe": is_safe,
            "mode": self.mode,
            "original_input": input_text if self.mode == "audit" else "[REDACTED]",
            "sanitized_input": sanitized_text,
            "prompt_injection_detected": is_injection,
            "prompt_injection_flags": injection_flags,
            "pii_detections_count": len(pii_detections),
            "pii_details": pii_detections,
            "bias_risk_score": bias_score,
            "bias_findings": bias_findings,
            "overall_risk_score": risk_score,
        }


def generate_reports(report_data: dict[str, Any], output_dir: Path) -> tuple[Path, Path, str]:
    """Generates JSON and Markdown audit reports with SHA-256 checksum integrity."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"ai_sec_guard_report_{timestamp_str}.json"
    md_path = output_dir / f"ai_sec_guard_report_{timestamp_str}.md"

    # Convert dictionary to JSON string
    raw_json = json.dumps(report_data, indent=2, ensure_ascii=False)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

    report_data_with_hash = dict(report_data)
    report_data_with_hash["audit_sha256"] = sha256_hash

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data_with_hash, f, indent=2, ensure_ascii=False)

    # Generate Markdown Report
    md_content = f"""# EU AI Act & OWASP LLM Security Audit Report

- **Timestamp (UTC):** {report_data['timestamp']}
- **Execution Mode:** `{report_data['mode']}`
- **Overall Safety Status:** `{'SAFE' if report_data['inspection']['is_safe'] else 'RISK_DETECTED'}`
- **Overall Risk Score:** `{report_data['inspection']['overall_risk_score']}`
- **Audit Evidence SHA-256:** `{sha256_hash}`

## Inspection Details
- **Prompt Injection Detected:** `{report_data['inspection']['prompt_injection_detected']}`
- **Injection Flags:** {json.dumps(report_data['inspection']['prompt_injection_flags'])}
- **PII Elements Redacted:** `{report_data['inspection']['pii_detections_count']}`
- **Bias Risk Score:** `{report_data['inspection']['bias_risk_score']}`

## Sanitized Prompt Output
```text
{report_data['inspection']['sanitized_input']}
```
"""
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return json_path, md_path, sha256_hash


def main() -> None:
    parser = argparse.ArgumentParser(description="EU AI Act & OWASP LLM Inference Safety & Governance Gateway")
    parser.add_argument("--input", type=str, required=True, help="Input prompt text to scan")
    parser.add_argument("--mode", type=str, choices=["enforce", "audit"], default="enforce", help="Execution mode")
    parser.add_argument("--output-dir", type=str, default="./reports", help="Directory to save audit reports")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without blocking execution")

    args = parser.parse_args()

    try:
        guard = AISecurityGuard(mode=args.mode)
        inspection_result = guard.inspect(args.input)

        report_payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "frameworks": ["EU AI Act Art. 15", "OWASP LLM01", "OWASP LLM02", "OWASP LLM09"],
            "dry_run": args.dry_run,
            "mode": args.mode,
            "inspection": inspection_result,
        }

        out_path = Path(args.output_dir)
        _json_file, _md_file, _report_sha = generate_reports(report_payload, out_path)


        if not inspection_result["is_safe"] and args.mode == "enforce" and not args.dry_run:
            sys.exit(1)

    except Exception:
        sys.exit(2)


if __name__ == "__main__":
    main()
