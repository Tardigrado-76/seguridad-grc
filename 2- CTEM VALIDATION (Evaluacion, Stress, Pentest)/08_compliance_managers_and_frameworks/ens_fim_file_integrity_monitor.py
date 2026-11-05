#!/usr/bin/env python3
"""
ens_fim_file_integrity_monitor.py
ENS RD 311/2022 [op.exp.7] File Integrity Monitoring (FIM) & System Hash Validation.
Signs and verifies an integrity baseline using SHA-256 signed JSON manifest.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class FIMVerificationResult:
    is_valid: bool
    manifest_signature_valid: bool
    tampered_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)


class ENSFIMMonitor:
    """
    Minimalist FIM Monitor for critical system binaries, configurations, and DLLs.
    Implements SHA-256 baseline hashing and cryptographically signed manifest verification.
    """

    def __init__(self, manifest_path: str | Path | None = None):
        self.manifest_path = Path(manifest_path) if manifest_path else Path(".integrity_manifest.json")

    @staticmethod
    def compute_sha256(filepath: Path) -> str:
        """Compute SHA-256 hex digest of a file in 64KB chunks."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def compute_manifest_signature(files_dict: dict[str, str]) -> str:
        """Compute a deterministic SHA-256 signature over sorted file hashes."""
        serialized = json.dumps(files_dict, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def generate_baseline(self, scan_dirs: list[str | Path]) -> dict:
        """Scan target directories, generate file hashes, sign manifest and save JSON."""
        file_hashes: dict[str, str] = {}

        for sdir in scan_dirs:
            p_dir = Path(sdir).resolve()
            if not p_dir.exists():
                continue
            for root, _, files in os.walk(p_dir):
                for fname in files:
                    full_p = Path(root) / fname
                    # Avoid hashing the manifest itself
                    if full_p.resolve() == self.manifest_path.resolve():
                        continue
                    rel_p = str(full_p.relative_to(p_dir)).replace("\\", "/")
                    file_hashes[rel_p] = self.compute_sha256(full_p)

        signature = self.compute_manifest_signature(file_hashes)
        manifest_data = {
            "version": "1.0.0",
            "algorithm": "SHA-256",
            "signature_sha256": signature,
            "total_files": len(file_hashes),
            "files": file_hashes,
        }

        with open(self.manifest_path, "w", encoding="utf-8") as fp:
            json.dump(manifest_data, fp, indent=2)

        return manifest_data

    def verify_integrity(self, base_dir: str | Path) -> FIMVerificationResult:
        """Verify files in base_dir against the signed JSON manifest."""
        if not self.manifest_path.exists():
            return FIMVerificationResult(
                is_valid=False,
                manifest_signature_valid=False,
                tampered_files=["MANIFEST_NOT_FOUND"],
            )

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as fp:
                manifest_data = json.load(fp)
        except (json.JSONDecodeError, OSError):
            return FIMVerificationResult(
                is_valid=False,
                manifest_signature_valid=False,
                tampered_files=["CORRUPT_MANIFEST"],
            )

        files_dict = manifest_data.get("files", {})
        expected_sig = manifest_data.get("signature_sha256", "")
        calculated_sig = self.compute_manifest_signature(files_dict)

        if expected_sig != calculated_sig:
            return FIMVerificationResult(
                is_valid=False,
                manifest_signature_valid=False,
                tampered_files=["MANIFEST_SIGNATURE_TAMPERED"],
            )

        base_p = Path(base_dir).resolve()
        tampered: list[str] = []
        missing: list[str] = []

        for rel_p, expected_hash in files_dict.items():
            current_p = base_p / rel_p
            if not current_p.exists():
                missing.append(rel_p)
                continue
            if self.compute_sha256(current_p) != expected_hash:
                tampered.append(rel_p)

        is_valid = len(tampered) == 0 and len(missing) == 0

        return FIMVerificationResult(
            is_valid=is_valid,
            manifest_signature_valid=True,
            tampered_files=tampered,
            missing_files=missing,
        )
