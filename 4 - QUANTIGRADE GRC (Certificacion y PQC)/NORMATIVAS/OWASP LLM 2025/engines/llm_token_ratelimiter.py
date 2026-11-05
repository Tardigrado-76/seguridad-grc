#!/usr/bin/env python3
"""OWASP LLM04 Model Denial of Service (DoS) & Token Rate Limiter.

Implements a sliding-window Token Bucket rate-limiting algorithm per tenant/client_id
to protect LLM inferencing pipelines against asymmetric resource exhaustion, buffer overflow
attacks, and prompt-inflation attacks.

Standards: OWASP Top 10 for LLM (LLM04), NIST SP 800-53 (SC-5 Denial of Service Protection).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import time
from pathlib import Path
from typing import Any


class TokenBucketExhaustedError(Exception):
    """Raised when a client breaches their allocated LLM token rate-limit budget."""


class TokenBucket:
    """Sliding-window Token Bucket implementation for LLM token rate-limiting."""

    def __init__(self, capacity_tokens: int, refill_rate_per_sec: float) -> None:
        self.capacity_tokens: float = float(capacity_tokens)
        self.tokens: float = float(capacity_tokens)
        self.refill_rate_per_sec: float = refill_rate_per_sec
        self.last_refill_timestamp: float = time.time()

    def _refill(self) -> None:
        now = time.time()
        elapsed = now - self.last_refill_timestamp
        added_tokens = elapsed * self.refill_rate_per_sec
        self.tokens = min(self.capacity_tokens, self.tokens + added_tokens)
        self.last_refill_timestamp = now

    def consume(self, token_count: int) -> bool:
        self._refill()
        if self.tokens >= token_count:
            self.tokens -= token_count
            return True
        return False


class LLMTokenRateLimiter:
    """Multi-tenant LLM Token Rate Limiter Gatekeeper."""

    def __init__(
        self,
        max_tokens_per_min: int = 100000,
        max_requests_per_min: int = 60,
        dry_run: bool = False,
        output_dir: str = "./ratelimit_reports",
    ) -> None:
        self.max_tokens_per_min: int = max_tokens_per_min
        self.max_requests_per_min: int = max_requests_per_min
        self.dry_run: bool = dry_run
        self.output_dir: Path = Path(output_dir)

        # Refill rate = tokens per second
        self.refill_rate: float = float(max_tokens_per_min) / 60.0
        self.client_buckets: dict[str, TokenBucket] = {}
        self.audit_log: list[dict[str, Any]] = []

    def get_client_bucket(self, client_id: str) -> TokenBucket:
        if client_id not in self.client_buckets:
            self.client_buckets[client_id] = TokenBucket(
                capacity_tokens=self.max_tokens_per_min,
                refill_rate_per_sec=self.refill_rate,
            )
        return self.client_buckets[client_id]

    def evaluate_request(self, client_id: str, requested_tokens: int) -> dict[str, Any]:
        """Evaluate if an incoming LLM inferencing request is permitted based on token consumption budget."""
        bucket = self.get_client_bucket(client_id)
        tokens_before: float = bucket.tokens
        allowed: bool = bucket.consume(requested_tokens) if not self.dry_run else (bucket.tokens >= requested_tokens)

        timestamp_iso: str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        decision_status: str = "PERMITTED" if allowed else "RATE_LIMITED_LLM04"

        record: dict[str, Any] = {
            "timestamp_iso": timestamp_iso,
            "client_id": client_id,
            "requested_tokens": requested_tokens,
            "tokens_available_before": round(tokens_before, 2),
            "tokens_remaining_after": round(bucket.tokens, 2),
            "decision": decision_status,
            "dry_run": self.dry_run,
        }
        self.audit_log.append(record)

        if not allowed and not self.dry_run:
            msg = (
                f"OWASP LLM04 Rate Limit Breached: Client '{client_id}' requested {requested_tokens} tokens "
                f"but only {round(bucket.tokens, 1)} tokens are available in current bucket allocation."
            )
            raise TokenBucketExhaustedError(
                msg,
            )

        return record

    def generate_evidence_reports(self) -> tuple[Path, Path, str]:
        """Export evidence reports in JSON & MD with ISO-8601 and SHA-256 self-digest."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str: str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        iso_timestamp: str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        json_path: Path = self.output_dir / f"LLM04-RATELIMIT-{timestamp_str}.json"
        md_path: Path = self.output_dir / f"LLM04-RATELIMIT-{timestamp_str}.md"

        report_payload: dict[str, Any] = {
            "title": "OWASP LLM04 Model DoS Token Rate Limiter Audit",
            "timestamp_iso": iso_timestamp,
            "max_tokens_per_min": self.max_tokens_per_min,
            "dry_run": self.dry_run,
            "audit_trail": self.audit_log,
        }

        # Write initial JSON
        json_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

        # Compute SHA-256 integrity hash
        report_sha256: str = hashlib.sha256(json_path.read_bytes()).hexdigest().upper()

        # Update JSON with integrity hash
        report_payload["report_integrity_sha256"] = report_sha256
        json_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

        # Generate Markdown Report
        md_lines: list[str] = [
            "# OWASP LLM04 Model DoS Token Rate Limiter Report",
            "",
            f"- **Timestamp (ISO-8601):** `{iso_timestamp}`",
            f"- **Token Capacity / min:** `{self.max_tokens_per_min}`",
            f"- **Dry-Run Mode:** `{self.dry_run}`",
            f"- **Report Integrity SHA-256:** `{report_sha256}`",
            "",
            "## Inferencing Request Evaluation Log",
            "",
        ]

        if not self.audit_log:
            md_lines.append("*No requests evaluated.*")
        else:
            md_lines.append("| Client ID | Tokens Requested | Available Before | Remaining After | Decision |")
            md_lines.append("| --- | --- | --- | --- | --- |")
            for item in self.audit_log:
                md_lines.append(f"| `{item['client_id']}` | `{item['requested_tokens']}` | `{item['tokens_available_before']}` | `{item['tokens_remaining_after']}` | **`{item['decision']}`** |")

        md_path.write_text("\n".join(md_lines), encoding="utf-8")
        return json_path, md_path, report_sha256


def main() -> None:
    parser = argparse.ArgumentParser(description="OWASP LLM04 Model DoS Token Rate Limiter")
    parser.add_argument("--max-tokens-per-min", type=int, default=100000, help="Max tokens allowed per minute per tenant")
    parser.add_argument("--client-id", default="tenant_alpha", help="Client tenant identifier")
    parser.add_argument("--request-tokens", type=int, default=4500, help="Estimated tokens for incoming request")
    parser.add_argument("--dry-run", action="store_true", help="Simulate rate limit evaluation without state mutation")
    parser.add_argument("--output-dir", default="./ratelimit_reports", help="Directory for evidence reports")

    args = parser.parse_args()

    limiter = LLMTokenRateLimiter(
        max_tokens_per_min=args.max_tokens_per_min,
        dry_run=args.dry_run,
        output_dir=args.output_dir,
    )

    try:
        limiter.evaluate_request(args.client_id, args.request_tokens)
    except TokenBucketExhaustedError:
        sys.exit(1)

    _json_path, _md_path, _sha256_digest = limiter.generate_evidence_reports()


if __name__ == "__main__":
    main()
