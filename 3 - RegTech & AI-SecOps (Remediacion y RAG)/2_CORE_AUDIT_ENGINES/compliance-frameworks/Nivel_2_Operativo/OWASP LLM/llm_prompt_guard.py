"""
Module: llm_prompt_guard.py
Description: Production-ready enterprise component for Llm Prompt Guard.
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
llm_prompt_guard.py — Pre-RAG Ingestion Guardrail & Vector DB Protection.

Compliance Alignment:
 - OWASP LLM: LLM01 (Prompt Injection), LLM06 (Sensitive Data Disclosure)
 - EU AI Act: Data Governance & Vector Pipeline Protection
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


class RAGPromptGuardrail:
    """Pre-Ingestion Guardrail for RAG Pipelines to prevent vector store contamination

    and system prompt override attacks.
    """

    SYSTEM_OVERRIDE_PATTERNS: List[re.Pattern] = [
        re.compile(r"System\s*:\s*", re.IGNORECASE),
        re.compile(r"<\s*\|?\s*im_start\s*\|?\s*>", re.IGNORECASE),
        re.compile(r"\[\s*INST\s*\]", re.IGNORECASE),
        re.compile(r"\[\s*SYSTEM\s*PROMPT\s*\]", re.IGNORECASE),
        re.compile(r"```\s*system", re.IGNORECASE),
        re.compile(r"forget\s+all\s+rules", re.IGNORECASE),
    ]

    DELIMITER_PATTERNS: List[re.Pattern] = [
        re.compile(r"</?script[^>]*>", re.IGNORECASE),
        re.compile(r"<!--.*?-->", re.DOTALL),
        re.compile(r"<\?xml.*?\?>", re.IGNORECASE),
    ]

    PII_PATTERNS: Dict[str, re.Pattern] = {
        "DNI_NIE": re.compile(r"\b(\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b", re.IGNORECASE),
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "PHONE": re.compile(r"\b(?:\+34|0034)?[ -]?[6789]\d{2}[ -]?\d{3}[ -]?\d{3}\b"),
        "CREDIT_CARD": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    }

    def __init__(self, mode: str = "enforce") -> None:
        self.mode: str = mode

    def sanitize_delimiters(self, text: str) -> Tuple[str, List[str]]:
        """Neutralizes unsafe HTML/XML/Markdown delimiters."""
        sanitized = text
        flags: List[str] = []
        for pattern in self.DELIMITER_PATTERNS:
            if pattern.search(sanitized):
                flags.append(f"Neutralized malicious delimiter pattern: {pattern.pattern}")
                sanitized = pattern.sub("", sanitized)
        return sanitized, flags

    def sanitize_system_overrides(self, text: str) -> Tuple[str, List[str]]:
        """Strips attempts to override system prompts."""
        sanitized = text
        flags: List[str] = []
        for pattern in self.SYSTEM_OVERRIDE_PATTERNS:
            if pattern.search(sanitized):
                flags.append(f"Removed system prompt override pattern: {pattern.pattern}")
                sanitized = pattern.sub("[REMOVED_SYSTEM_INSTRUCTION]", sanitized)
        return sanitized, flags

    def redact_pii_for_embedding(self, text: str) -> Tuple[str, List[str]]:
        """Redacts sensitive PII before embedding to avoid Vector DB contamination."""
        sanitized = text
        flags: List[str] = []
        for pii_type, pattern in self.PII_PATTERNS.items():
            matches = pattern.findall(sanitized)
            if matches:
                flags.append(f"Redacted {len(matches)} instances of {pii_type}")
                sanitized = pattern.sub(f"[ANONYMIZED_{pii_type}]", sanitized)
        return sanitized, flags

    def evaluate_prompt(self, prompt: str) -> Dict[str, Any]:
        """Main guardrail pipeline returning structured evaluation."""
        flags: List[str] = []

        step1_text, flags1 = self.sanitize_delimiters(prompt)
        step2_text, flags2 = self.sanitize_system_overrides(step1_text)
        final_text, flags3 = self.redact_pii_for_embedding(step2_text)

        flags = flags1 + flags2 + flags3

        risk_score = round(min(1.0, len(flags) * 0.25), 2)
        is_safe = risk_score < 0.5 or self.mode == "audit"

        return {
            "is_safe": is_safe,
            "sanitized_prompt": final_text,
            "risk_score": risk_score,
            "flags": flags,
            "original_length": len(prompt),
            "sanitized_length": len(final_text),
        }


def save_audit_evidence(data: Dict[str, Any], output_dir: Path) -> Tuple[Path, Path, str]:
    """Generates JSON and MD reports with SHA-256 hash checksum."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_file = output_dir / f"llm_prompt_guard_report_{ts}.json"
    md_file = output_dir / f"llm_prompt_guard_report_{ts}.md"

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sha256 = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

    data_with_sha = dict(data)
    data_with_sha["report_sha256"] = sha256

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data_with_sha, f, indent=2, ensure_ascii=False)

    md_body = f"""# OWASP LLM & Pre-RAG Guardrail Evidence Report

- **Timestamp:** {data['timestamp']}
- **Mode:** `{data['mode']}`
- **Is Safe:** `{data['evaluation']['is_safe']}`
- **Risk Score:** `{data['evaluation']['risk_score']}`
- **SHA-256 Checksum:** `{sha256}`

## Flags & Detections
```json
{json.dumps(data['evaluation']['flags'], indent=2)}
```

## Sanitized Prompt (Vector DB Ready)
```text
{data['evaluation']['sanitized_prompt']}
```
"""
    with open(md_file, "w", encoding="utf-8") as f:
        f.write(md_body)

    return json_file, md_file, sha256


def main() -> None:
    parser = argparse.ArgumentParser(description="Pre-RAG Ingestion Guardrail & Sanitizer")
    parser.add_argument("--prompt", type=str, required=True, help="User prompt to evaluate")
    parser.add_argument("--mode", type=str, choices=["enforce", "audit"], default="enforce")
    parser.add_argument("--output-dir", type=str, default="./reports")
    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    try:
        guardrail = RAGPromptGuardrail(mode=args.mode)
        eval_result = guardrail.evaluate_prompt(args.prompt)

        payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "mode": args.mode,
            "dry_run": args.dry_run,
            "evaluation": eval_result,
        }

        out_dir = Path(args.output_dir)
        j_path, m_path, sha_digest = save_audit_evidence(payload, out_dir)

        logger.info(f"[+] RAG Guardrail Evaluation Completed.")
        logger.info(f"    Safe: {eval_result['is_safe']}")
        logger.info(f"    Risk Score: {eval_result['risk_score']}")
        logger.info(f"    JSON Evidence: {j_path}")
        logger.info(f"    MD Evidence: {m_path}")
        logger.info(f"    SHA-256 Digest: {sha_digest}")

        if not eval_result["is_safe"] and args.mode == "enforce" and not args.dry_run:
            logger.info("[-] [ENFORCE MODE] Blocked prompt from reaching Vector DB / Model.")
            sys.exit(1)

    except Exception as err:
        logger.info(f"[!] Error running llm_prompt_guard: {err}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
