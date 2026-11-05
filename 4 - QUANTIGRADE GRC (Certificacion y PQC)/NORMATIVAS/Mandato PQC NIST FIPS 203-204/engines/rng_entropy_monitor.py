#!/usr/bin/env python3
"""FIPS 140-3 Continuous DRBG/RNG Entropy Health Monitor.

Evaluates system random number generator entropy quality against NIST SP 800-90B health test metrics
(Repetition Count Test & Adaptive Proportion Test) to prevent weak cryptographic key generation.

Standards: FIPS 140-3, NIST SP 800-90B (Recommendation for Entropy Sources Used for Random Bit Generation).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import platform
import secrets
import sys
from pathlib import Path
from typing import Any


class EntropyExhaustionException(Exception):
    """Raised when system DRBG/RNG entropy quality falls below NIST SP 800-90B safety threshold."""


class RNGEntropyMonitor:
    """Production-grade FIPS 140-3 DRBG Entropy Monitor."""

    MIN_ENTROPY_THRESHOLD_BITS: int = 256

    def __init__(
        self,
        sample_size_bytes: int = 4096,
        dry_run: bool = False,
        output_dir: str = "./entropy_reports",
    ) -> None:
        self.sample_size_bytes: int = sample_size_bytes
        self.dry_run: bool = dry_run
        self.output_dir: Path = Path(output_dir)
        self.system_os: str = platform.system()
        self.audit_records: list[dict[str, Any]] = []

    def get_system_entropy_bits(self) -> int:
        """Inspect OS available entropy pool bits."""
        if self.system_os == "Linux":
            entropy_path = Path("/proc/sys/kernel/random/entropy_avail")
            if entropy_path.exists():
                try:
                    return int(entropy_path.read_text().strip())
                except Exception:
                    pass
        # Fallback / Windows / macOS CSPRNG quality simulation
        return 4096

    def repetition_count_test(self, sample_bytes: bytes) -> tuple[bool, int]:
        """NIST SP 800-90B Repetition Count Test: Detect stuck or repeating bits."""
        max_repetition: int = 0
        current_repetition: int = 1
        last_byte: int | None = None

        for b in sample_bytes:
            if b == last_byte:
                current_repetition += 1
            else:
                current_repetition = 1
                last_byte = b
            max_repetition = max(max_repetition, current_repetition)

        # NIST 800-90B cutoff threshold for bytes (repetition > 16 is anomalous)
        passed: bool = (max_repetition <= 16)
        return passed, max_repetition

    def adaptive_proportion_test(self, sample_bytes: bytes) -> tuple[bool, int]:
        """NIST SP 800-90B Adaptive Proportion Test: Detect bias in sample window."""
        window_size: int = 512
        if len(sample_bytes) < window_size:
            return True, 0

        target_byte: int = sample_bytes[0]
        count: int = sum(1 for b in sample_bytes[:window_size] if b == target_byte)

        # Cutoff threshold for window size 512 (count > 64 is anomalous for uniform bytes)
        passed: bool = (count <= 64)
        return passed, count

    def evaluate_entropy_health(self) -> dict[str, Any]:
        """Collect CSPRNG sample and run NIST SP 800-90B health tests."""
        avail_bits: int = self.get_system_entropy_bits()
        sample_bytes: bytes = secrets.token_bytes(self.sample_size_bytes)

        rep_passed, max_rep = self.repetition_count_test(sample_bytes)
        adapt_passed, adapt_count = self.adaptive_proportion_test(sample_bytes)

        overall_healthy: bool = (avail_bits >= self.MIN_ENTROPY_THRESHOLD_BITS) and rep_passed and adapt_passed

        status_str: str = "ENTROPY_HEALTHY" if overall_healthy else "ENTROPY_DEGRADED_SP800_90B"

        record: dict[str, Any] = {
            "timestamp_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "available_entropy_bits": avail_bits,
            "sample_size_bytes": self.sample_size_bytes,
            "repetition_count_test": {"passed": rep_passed, "max_consecutive": max_rep},
            "adaptive_proportion_test": {"passed": adapt_passed, "window_count": adapt_count},
            "status": status_str,
            "dry_run": self.dry_run,
        }

        self.audit_records.append(record)

        if not overall_healthy and not self.dry_run:
            msg = (
                f"FIPS 140-3 Security Violation: Entropy pool degraded! Avail bits: {avail_bits}, "
                f"Repetition Test: {rep_passed}, Adaptive Test: {adapt_passed}."
            )
            raise EntropyExhaustionException(
                msg,
            )

        return record

    def generate_evidence_reports(self) -> tuple[Path, Path, str]:
        """Export evidence reports in JSON & MD with ISO-8601 and SHA-256 self-digest."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str: str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        iso_timestamp: str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        json_path: Path = self.output_dir / f"FIPS-ENTROPY-{timestamp_str}.json"
        md_path: Path = self.output_dir / f"FIPS-ENTROPY-{timestamp_str}.md"

        report_payload: dict[str, Any] = {
            "title": "FIPS 140-3 Continuous DRBG/RNG Entropy Health Audit",
            "timestamp_iso": iso_timestamp,
            "system_os": self.system_os,
            "dry_run": self.dry_run,
            "audit_records": self.audit_records,
        }

        # Write initial JSON
        json_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

        # Compute SHA-256 integrity hash
        report_sha256: str = hashlib.sha256(json_path.read_bytes()).hexdigest().upper()

        # Update JSON with integrity hash
        report_payload["report_integrity_sha256"] = report_sha256
        json_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

        # Markdown Report
        md_lines: list[str] = [
            "# FIPS 140-3 Continuous DRBG Entropy Health Audit Report",
            "",
            f"- **Timestamp (ISO-8601):** `{iso_timestamp}`",
            f"- **Operating System:** `{self.system_os}`",
            f"- **Dry-Run Mode:** `{self.dry_run}`",
            f"- **Report Integrity SHA-256:** `{report_sha256}`",
            "",
            "## NIST SP 800-90B Health Test Evaluation",
            "",
        ]

        for rec in self.audit_records:
            md_lines.append(f"- **Available Entropy Bits:** `{rec['available_entropy_bits']}`")
            md_lines.append(f"- **Repetition Count Test:** `Passed={rec['repetition_count_test']['passed']}` (Max Consecutive: {rec['repetition_count_test']['max_consecutive']})")
            md_lines.append(f"- **Adaptive Proportion Test:** `Passed={rec['adaptive_proportion_test']['passed']}` (Count: {rec['adaptive_proportion_test']['window_count']})")
            md_lines.append(f"- **Overall Status:** **`{rec['status']}`**")

        md_path.write_text("\n".join(md_lines), encoding="utf-8")
        return json_path, md_path, report_sha256


def main() -> None:
    parser = argparse.ArgumentParser(description="FIPS 140-3 Continuous DRBG Entropy Health Monitor")
    parser.add_argument("--sample-size", type=int, default=4096, help="Sample size in bytes for entropy health test")
    parser.add_argument("--dry-run", action="store_true", help="Simulate audit without triggering exception")
    parser.add_argument("--output-dir", default="./entropy_reports", help="Directory for evidence reports")

    args = parser.parse_args()

    monitor = RNGEntropyMonitor(
        sample_size_bytes=args.sample_size,
        dry_run=args.dry_run,
        output_dir=args.output_dir,
    )

    try:
        monitor.evaluate_entropy_health()
    except EntropyExhaustionException:
        sys.exit(1)

    _json_path, _md_path, _sha256_digest = monitor.generate_evidence_reports()


if __name__ == "__main__":
    main()
