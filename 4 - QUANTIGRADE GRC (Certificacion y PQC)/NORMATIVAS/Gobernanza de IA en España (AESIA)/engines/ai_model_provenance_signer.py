#!/usr/bin/env python3
"""EU AI Act & Supply Chain Model Provenance Signer & Runtime Anti-Poisoning Guard.

Calculates cryptographic hashes (SHA-256 / SHA-512) for AI model weights (.safetensors, .pt, .onnx),
signs and verifies model provenance attestation signatures, and provides a runtime loader guard
to block memory allocation of poisoned or altered AI models.

Standards: EU AI Act (Arts. 10, 15), SLSA Level 3+, NIST SP 800-218 (SSDF).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, ClassVar


class ModelPoisoningError(Exception):
    """Raised when an AI model file hash or signature check fails prior to memory loading."""


class AIModelProvenanceSigner:
    """Production-grade Model Provenance Signer and Anti-Poisoning Guard."""

    SUPPORTED_EXTENSIONS: ClassVar[set[str]] = {
        ".safetensors",
        ".pt",
        ".pth",
        ".onnx",
        ".bin",
        ".h5",
    }

    def __init__(
        self,
        model_path: str,
        secret_key: str | None = None,
        dry_run: bool = False,
        output_dir: str = "./provenance_reports",
    ) -> None:
        self.model_file: Path = Path(model_path)
        self.secret_key: str = secret_key or "SYSTEM_DEFAULT_SIGSTORE_SECRET_KEY_V1"
        self.dry_run: bool = dry_run
        self.output_dir: Path = Path(output_dir)
        self.audit_trail: list[dict[str, Any]] = []

    def compute_model_digest(self) -> dict[str, str]:
        """Compute SHA-256 and SHA-512 cryptographic digests for model file."""
        if not self.model_file.exists():
            msg = f"Model file '{self.model_file}' does not exist."
            raise FileNotFoundError(msg)

        sha256_hash = hashlib.sha256()
        sha512_hash = hashlib.sha512()

        # Read in 1MB chunks to handle multi-GB weights efficiently
        chunk_size: int = 1024 * 1024
        with open(self.model_file, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)
                sha512_hash.update(chunk)

        digests: dict[str, str] = {
            "sha256": sha256_hash.hexdigest().upper(),
            "sha512": sha512_hash.hexdigest().upper(),
            "size_bytes": str(self.model_file.stat().st_size),
        }
        return digests

    def sign_model_provenance(self) -> dict[str, Any]:
        """Generate HMAC-SHA256 signature attestation for model provenance."""
        digests = self.compute_model_digest()
        payload: str = (
            f"{self.model_file.name}:{digests['sha256']}:{digests['size_bytes']}"
        )

        signature: str = (
            hashlib.pbkdf2_hmac(
                "sha256",
                payload.encode("utf-8"),
                self.secret_key.encode("utf-8"),
                100000,
            )
            .hex()
            .upper()
        )

        attestation: dict[str, Any] = {
            "model_name": self.model_file.name,
            "digests": digests,
            "signature_hmac_sha256": signature,
            "created_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "provenance_status": "SIGNED",
        }

        if not self.dry_run:
            sig_file: Path = self.model_file.with_suffix(
                self.model_file.suffix + ".sig.json"
            )
            sig_file.write_text(json.dumps(attestation, indent=2), encoding="utf-8")
            attestation["signature_file"] = str(sig_file)

        self.audit_trail.append(attestation)
        return attestation

    def verify_model_provenance(
        self, sig_file_path: str | None = None
    ) -> tuple[bool, str]:
        """Verify model file integrity against stored signature attestation."""
        sig_path: Path = (
            Path(sig_file_path)
            if sig_file_path
            else self.model_file.with_suffix(self.model_file.suffix + ".sig.json")
        )

        if not sig_path.exists():
            return False, f"Signature attestation file '{sig_path}' not found."

        try:
            attestation_raw: str = sig_path.read_text(encoding="utf-8")
            attestation: dict[str, Any] = json.loads(attestation_raw)

            stored_sha256: str = attestation["digests"]["sha256"]
            stored_sig: str = attestation["signature_hmac_sha256"]

            current_digests = self.compute_model_digest()

            if current_digests["sha256"] != stored_sha256:
                return (
                    False,
                    f"HASH MISMATCH! Stored SHA256 '{stored_sha256}' != Current '{current_digests['sha256']}'",
                )

            payload: str = f"{self.model_file.name}:{current_digests['sha256']}:{current_digests['size_bytes']}"
            expected_sig: str = (
                hashlib.pbkdf2_hmac(
                    "sha256",
                    payload.encode("utf-8"),
                    self.secret_key.encode("utf-8"),
                    100000,
                )
                .hex()
                .upper()
            )

            if stored_sig != expected_sig:
                return (
                    False,
                    "SIGNATURE INVALID! Secret key or attestation payload altered.",
                )

            return True, "PROVENANCE_VERIFIED_CLEAN"

        except (json.JSONDecodeError, OSError, KeyError, ValueError) as exc:
            return False, f"Verification failed: {exc}"

    def guard_model_load(self) -> None:
        """Runtime guard function: raises ModelPoisoningError if verification fails."""
        is_valid, reason = self.verify_model_provenance()
        if not is_valid:
            msg = f"EU AI Act Security Violation: Refusing to load poisoned AI model '{self.model_file.name}'. Reason: {reason}"
            raise ModelPoisoningError(
                msg,
            )

    def generate_evidence_reports(self) -> tuple[Path, Path, str]:
        """Export evidence reports in JSON & MD with ISO-8601 and SHA-256 self-digest."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str: str = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
        iso_timestamp: str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        json_path: Path = self.output_dir / f"AI-PROVENANCE-{timestamp_str}.json"
        md_path: Path = self.output_dir / f"AI-PROVENANCE-{timestamp_str}.md"

        report_payload: dict[str, Any] = {
            "title": "EU AI Act Model Provenance & Anti-Poisoning Audit",
            "timestamp_iso": iso_timestamp,
            "model_path": str(self.model_file),
            "dry_run": self.dry_run,
            "audit_records": self.audit_trail,
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
            "# EU AI Act & Supply Chain Model Provenance Audit Report",
            "",
            f"- **Timestamp (ISO-8601):** `{iso_timestamp}`",
            f"- **Target Model:** `{self.model_file.name}`",
            f"- **Dry-Run Mode:** `{self.dry_run}`",
            f"- **Report Integrity SHA-256:** `{report_sha256}`",
            "",
            "## Attestation Records",
            "",
        ]

        for rec in self.audit_trail:
            md_lines.append(f"### Model: `{rec.get('model_name')}`")
            md_lines.append(f"- **Status:** `{rec.get('provenance_status')}`")
            md_lines.append(f"- **SHA-256:** `{rec.get('digests', {}).get('sha256')}`")
            md_lines.append(f"- **Signature:** `{rec.get('signature_hmac_sha256')}`")
            md_lines.append("")

        md_path.write_text("\n".join(md_lines), encoding="utf-8")
        return json_path, md_path, report_sha256


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EU AI Act Model Provenance Signer & Anti-Poisoning Guard"
    )
    parser.add_argument(
        "--model-path",
        required=True,
        help="Path to AI model weights file (.safetensors, .pt, .onnx)",
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=["sign", "verify", "guard-load"],
        help="Action to execute",
    )
    parser.add_argument(
        "--secret-key", help="Secret key for HMAC signature generation/verification"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate signing/verification without file writes",
    )
    parser.add_argument(
        "--output-dir",
        default="./provenance_reports",
        help="Directory for evidence reports",
    )

    args = parser.parse_args()

    signer = AIModelProvenanceSigner(
        model_path=args.model_path,
        secret_key=args.secret_key,
        dry_run=args.dry_run,
        output_dir=args.output_dir,
    )

    if args.action == "sign":
        signer.sign_model_provenance()
    elif args.action == "verify":
        _is_valid, _reason = signer.verify_model_provenance()
    elif args.action == "guard-load":
        try:
            signer.guard_model_load()
        except ModelPoisoningError:
            sys.exit(1)

    _json_path, _md_path, _sha256_digest = signer.generate_evidence_reports()


if __name__ == "__main__":
    main()
