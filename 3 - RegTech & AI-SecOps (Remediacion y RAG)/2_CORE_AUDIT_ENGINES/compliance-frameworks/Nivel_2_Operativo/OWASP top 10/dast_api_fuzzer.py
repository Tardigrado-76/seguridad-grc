"""
Module: dast_api_fuzzer.py
Description: Production-ready enterprise component for Dast Api Fuzzer.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


import os
import logging
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

#!/usr/bin/env python3
"""
OWASP Top 10 Dynamic Application Security Testing (DAST) & API Fuzzer.

Performs automated boundary value mutation, SQLi/XSS payload injection, header fuzzing,
and unhandled HTTP 500 error detection on HTTP/REST API endpoints.

Standards: OWASP Top 10 (2025), NIST SP 800-115 (Technical Guide to Information Security Testing).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class DASTApiFuzzer:
    """Production-grade Dynamic API Security Fuzzer."""

    MUTATION_PAYLOADS: List[Dict[str, str]] = [
        {"name": "SQLi_Union", "payload": "' UNION SELECT NULL, @@version, user() -- "},
        {"name": "XSS_Polyglot", "payload": "javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>"},
        {"name": "Path_Traversal", "payload": "../../../../../etc/passwd\x00"},
        {"name": "Command_Injection", "payload": "; cat /etc/passwd | grep -v root #"},
        {"name": "Format_String", "payload": "%s%p%x%d%n%s%p%x%d%n"},
        {"name": "Large_Buffer_Overflow", "payload": "A" * 8192},
        {"name": "Malformed_JSON", "payload": '{"key": "value", "unterminated": }'}
    ]

    def __init__(
        self,
        target_url: str,
        http_method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        dry_run: bool = False,
        output_dir: str = "./dast_reports"
    ) -> None:
        self.target_url: str = target_url
        self.http_method: str = http_method.upper()
        self.headers: Dict[str, str] = headers or {"Content-Type": "application/json", "User-Agent": "DAST-Fuzzer-Engine/1.0"}
        self.dry_run: bool = dry_run
        self.output_dir: Path = Path(output_dir)
        self.vulnerabilities_detected: List[Dict[str, Any]] = []

    def _send_fuzz_request(self, payload_name: str, payload_str: str) -> Dict[str, Any]:
        """Send mutated HTTP request to target endpoint and evaluate status code and response."""
        result: Dict[str, Any] = {
            "payload_name": payload_name,
            "status_code": 0,
            "vulnerability_found": False,
            "details": ""
        }

        if self.dry_run:
            result["status_code"] = 200
            result["details"] = "SIMULATED_REQUEST_SUCCESS (Dry-Run)"
            return result

        try:
            data_bytes: bytes = json.dumps({"fuzz_input": payload_str}).encode("utf-8")
            req = urllib.request.Request(self.target_url, data=data_bytes, headers=self.headers, method=self.http_method)

            with urllib.request.urlopen(req, timeout=5.0) as resp:
                result["status_code"] = resp.status
                resp_body: str = resp.read().decode("utf-8", errors="ignore")

                # Check for standard error leak patterns
                if any(err_kw in resp_body.lower() for err_kw in ["sql syntax", "traceback", "fatal error", "exception"]):
                    result["vulnerability_found"] = True
                    result["details"] = "ERROR_LEAK_DETECTED: Stack trace or DB syntax error exposed in HTTP 200 body."

        except urllib.error.HTTPError as http_err:
            result["status_code"] = http_err.code
            if http_err.code >= 500:
                result["vulnerability_found"] = True
                result["details"] = f"CRITICAL_SERVER_CRASH: Server returned HTTP {http_err.code} on payload '{payload_name}'."
            else:
                result["details"] = f"Handled Client Error HTTP {http_err.code}."
        except urllib.error.URLError as url_err:
            result["status_code"] = 0
            result["details"] = f"Connection failed: {url_err.reason}"
        except Exception as exc:
            result["status_code"] = 0
            result["details"] = f"Unexpected client error: {exc}"

        return result

    def run_fuzzing_suite(self) -> List[Dict[str, Any]]:
        """Run complete mutational fuzzing suite against target endpoint."""
        logger.info(f"[DAST FUZZER] Starting attack surface scan on '{self.target_url}' (Dry-Run: {self.dry_run})...")

        for p in self.MUTATION_PAYLOADS:
            res = self._send_fuzz_request(p["name"], p["payload"])
            if res["vulnerability_found"]:
                self.vulnerabilities_detected.append(res)
                logger.info(f"  [VULNERABILITY DETECTED] Payload: {p['name']} | Status: {res['status_code']} | Details: {res['details']}")
            else:
                logger.info(f"  [PASS] Payload: {p['name']} | Status: {res['status_code']}")

        return self.vulnerabilities_detected

    def generate_evidence_reports(self) -> Tuple[Path, Path, str]:
        """Export evidence reports in JSON & MD with ISO-8601 and SHA-256 self-digest."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str: str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        iso_timestamp: str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        json_path: Path = self.output_dir / f"DAST-AUDIT-{timestamp_str}.json"
        md_path: Path = self.output_dir / f"DAST-AUDIT-{timestamp_str}.md"

        report_payload: Dict[str, Any] = {
            "title": "OWASP Top 10 Dynamic Application Security Testing (DAST) Audit",
            "timestamp_iso": iso_timestamp,
            "target_url": self.target_url,
            "http_method": self.http_method,
            "dry_run": self.dry_run,
            "total_payloads_tested": len(self.MUTATION_PAYLOADS),
            "vulnerabilities_count": len(self.vulnerabilities_detected),
            "vulnerabilities": self.vulnerabilities_detected
        }

        # Write initial JSON
        json_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

        # Compute SHA-256 integrity hash
        report_sha256: str = hashlib.sha256(json_path.read_bytes()).hexdigest().upper()

        # Update JSON with integrity hash
        report_payload["report_integrity_sha256"] = report_sha256
        json_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

        # Markdown Report
        md_lines: List[str] = [
            "# OWASP Top 10 DAST API Fuzzer Report",
            "",
            f"- **Timestamp (ISO-8601):** `{iso_timestamp}`",
            f"- **Target Endpoint:** `{self.target_url}`",
            f"- **HTTP Method:** `{self.http_method}`",
            f"- **Payloads Tested:** `{len(self.MUTATION_PAYLOADS)}`",
            f"- **Dry-Run Mode:** `{self.dry_run}`",
            f"- **Report Integrity SHA-256:** `{report_sha256}`",
            "",
            "## Vulnerability Finding Summary",
            f"- **Vulnerabilities Count:** `{len(self.vulnerabilities_detected)}`",
            ""
        ]

        if not self.vulnerabilities_detected:
            md_lines.append("*No unhandled HTTP 500 crashes or error leaks detected during fuzzing.*")
        else:
            md_lines.append("| Payload Name | HTTP Status | Details |")
            md_lines.append("| --- | --- | --- |")
            for vul in self.vulnerabilities_detected:
                md_lines.append(f"| `{vul['payload_name']}` | `{vul['status_code']}` | `{vul['details']}` |")

        md_path.write_text("\n".join(md_lines), encoding="utf-8")
        return json_path, md_path, report_sha256


def main() -> None:
    parser = argparse.ArgumentParser(description="OWASP Top 10 DAST API Fuzzer Engine")
    parser.add_argument("--target-url", required=True, help="Target API endpoint URL to fuzz")
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT"], help="HTTP Method")
    parser.add_argument("--dry-run", action="store_true", help="Simulate fuzzing without executing network requests")
    parser.add_argument("--output-dir", default="./dast_reports", help="Directory for evidence reports")

    args = parser.parse_args()

    fuzzer = DASTApiFuzzer(
        target_url=args.target_url,
        http_method=args.method,
        dry_run=args.dry_run,
        output_dir=args.output_dir
    )

    fuzzer.run_fuzzing_suite()
    json_path, md_path, sha256_digest = fuzzer.generate_evidence_reports()

    logger.info("\n[EVIDENCE TRAIL] DAST Audit reports generated successfully:")
    logger.info(f"  - JSON Report: {json_path}")
    logger.info(f"  - MD Report:   {md_path}")
    logger.info(f"  - SHA256 Hash: {sha256_digest}")


if __name__ == "__main__":
    main()
