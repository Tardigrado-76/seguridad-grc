#!/usr/bin/env python3
"""immutable_log_verifier.py - Cryptographic Hash-Chained Log & Merkle Tree Verifier.

Compliance Alignment:
 - DORA (EU 2022/2554) Art. 10 (Audit logging, immutability & non-repudiation)
 - ENS RD 311/2022: Medida [op.exp.8] Registro de Actividad e Integridad
 - ISO/IEC 27001:2022 Control A.8.15 (Logging) & ISO/IEC 27037 (Digital Evidence)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ImmutableLogVerifier")


@dataclass
class LogEntryValidation:
    """Individual log record cryptographic verification result."""
    line_number: int
    raw_content: str
    entry_hash: str
    expected_previous_hash: str
    calculated_previous_hash: str
    is_valid: bool
    error_detail: str | None = None


@dataclass
class MerkleTreeResult:
    """Merkle Tree aggregation result."""
    root_hash: str
    total_leafs: int
    tree_depth: int
    leaf_hashes: list[str]


@dataclass
class LogIntegrityReport:
    """Consolidated log immutability and compliance report."""
    log_file_path: str
    timestamp: str
    total_lines_scanned: int
    valid_lines_count: int
    tampered_lines_count: int
    is_integrity_intact: bool
    merkle_root_hash: str
    chain_broken_at_line: int | None
    tampered_entries: list[dict[str, Any]]
    dora_compliance_status: str


class MerkleTreeBuilder:
    """Calculates SHA-256 Merkle Tree over a sequence of log entry digests."""

    @staticmethod
    def compute_sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @classmethod
    def build_merkle_tree(cls, hashes: list[str]) -> MerkleTreeResult:
        if not hashes:
            empty_root = cls.compute_sha256("")
            return MerkleTreeResult(root_hash=empty_root, total_leafs=0, tree_depth=0, leaf_hashes=[])

        current_level = list(hashes)
        depth = 0

        while len(current_level) > 1:
            depth += 1
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = cls.compute_sha256(left + right)
                next_level.append(combined)
            current_level = next_level

        return MerkleTreeResult(
            root_hash=current_level[0],
            total_leafs=len(hashes),
            tree_depth=depth,
            leaf_hashes=hashes,
        )


class ImmutableLogVerifier:
    """Verifies SHA-256 hash-chained log files and builds Merkle Trees for DORA Art. 10."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, log_path: Path | str) -> None:
        self.log_path = Path(log_path)

    @classmethod
    def create_chained_log_file(cls, target_path: Path | str, num_entries: int = 10) -> Path:
        """Creates a synthetic hash-chained immutable log file for testing."""
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        prev_hash = cls.GENESIS_HASH

        sample_events = [
            "USER_LOGIN_SUCCESS user=admin ip=192.168.1.50 mfa=ENABLED",
            "CONFIG_CHANGE component=WAF policy=BLOCK_SQLI action=UPDATE",
            "BACKUP_COMPLETED target=DB_PRIMARY size=45GB duration=12m",
            "ALERT_TRIGGERED rule=LARGE_DATA_EXPORT threshold=EXCEEDED",
            "IAM_ROLE_ASSIGNED user=jdoe role=SecOpsManager",
            "KEY_ROTATION status=SUCCESS key_id=KMS-EU-9921",
            "API_CALL endpoint=/v1/transfers status=200 latency=45ms",
            "FIREWALL_RULE_ADDED src=10.0.4.0/24 dst=8.8.8.8 action=ALLOW",
            "SESSION_TERMINATED user=admin reason=TIMEOUT",
            "AUDIT_CHECKPOINT status=OK merkle_sync=TRUE",
        ]

        with path.open("w", encoding="utf-8") as f:
            for i in range(num_entries):
                ts = (
                    datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(minutes=num_entries - i)
                ).isoformat()
                payload = sample_events[i % len(sample_events)]
                entry_data = f"{ts}|{payload}|{prev_hash}"
                current_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()

                # Format: TIMESTAMP | PAYLOAD | PREV_HASH | CURRENT_HASH
                f.write(f"{ts} | {payload} | {prev_hash} | {current_hash}\n")
                prev_hash = current_hash

        return path

    def verify_integrity(self) -> LogIntegrityReport:
        """Audits the hash chain and computes the Merkle Root of the log file."""
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file does not exist: {self.log_path}")

        lines_scanned = 0
        valid_count = 0
        tampered_count = 0
        expected_prev_hash = self.GENESIS_HASH
        first_broken_line: int | None = None
        tampered_list: list[LogEntryValidation] = []
        leaf_hashes: list[str] = []

        with self.log_path.open(encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                line_str = line.strip()
                if not line_str:
                    continue

                lines_scanned += 1
                parts = [p.strip() for p in line_str.split("|")]

                if len(parts) < 4:
                    tampered_count += 1
                    if first_broken_line is None:
                        first_broken_line = line_idx
                    tampered_list.append(
                        LogEntryValidation(
                            line_number=line_idx,
                            raw_content=line_str,
                            entry_hash="",
                            expected_previous_hash=expected_prev_hash,
                            calculated_previous_hash="FORMAT_ERROR",
                            is_valid=False,
                            error_detail="Invalid delimiter count in log line",
                        )
                    )
                    continue

                ts, payload, prev_hash_in_log, current_hash_in_log = parts[0], parts[1], parts[2], parts[3]

                chain_ok = (prev_hash_in_log == expected_prev_hash)
                recomputed_data = f"{ts}|{payload}|{prev_hash_in_log}"
                recomputed_hash = hashlib.sha256(recomputed_data.encode("utf-8")).hexdigest()
                hash_ok = (recomputed_hash == current_hash_in_log)

                is_line_valid = chain_ok and hash_ok

                if is_line_valid:
                    valid_count += 1
                    leaf_hashes.append(current_hash_in_log)
                    expected_prev_hash = current_hash_in_log
                else:
                    tampered_count += 1
                    if first_broken_line is None:
                        first_broken_line = line_idx

                    err_msg = []
                    if not chain_ok:
                        err_msg.append(f"Chain broken (Expected previous: {expected_prev_hash[:12]}..., got: {prev_hash_in_log[:12]}...)")
                    if not hash_ok:
                        err_msg.append(f"Content forged (Computed: {recomputed_hash[:12]}..., recorded: {current_hash_in_log[:12]}...)")

                    tampered_list.append(
                        LogEntryValidation(
                            line_number=line_idx,
                            raw_content=line_str,
                            entry_hash=current_hash_in_log,
                            expected_previous_hash=expected_prev_hash,
                            calculated_previous_hash=prev_hash_in_log,
                            is_valid=False,
                            error_detail="; ".join(err_msg),
                        )
                    )
                    expected_prev_hash = current_hash_in_log

        merkle_res = MerkleTreeBuilder.build_merkle_tree(leaf_hashes)
        is_intact = (tampered_count == 0) and (lines_scanned > 0)
        compliance = "CONFORME_DORA_ART10" if is_intact else "NO_CONFORME_MODIFICACION_DETECTADA"

        return LogIntegrityReport(
            log_file_path=str(self.log_path.resolve()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            total_lines_scanned=lines_scanned,
            valid_lines_count=valid_count,
            tampered_lines_count=tampered_count,
            is_integrity_intact=is_intact,
            merkle_root_hash=merkle_res.root_hash,
            chain_broken_at_line=first_broken_line,
            tampered_entries=[asdict(t) for t in tampered_list],
            dora_compliance_status=compliance,
        )

    def export_json(self, report: LogIntegrityReport, output_path: Path | str) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(asdict(report), indent=2, ensure_ascii=False), encoding="utf-8")
        return out


# Alias for compatibility with DORA terminology
DORALogImmutabilityVerifier = ImmutableLogVerifier


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit Log Immutability & Merkle Verifier (DORA Art. 10)")
    parser.add_argument("--log-file", type=Path, help="Path to log file to audit")
    parser.add_argument("--create-sample-log", type=Path, help="Create a sample immutable log")
    parser.add_argument("--output-dir", type=Path, default=Path("./log_verification_output"))

    args = parser.parse_args()

    if args.create_sample_log:
        ImmutableLogVerifier.create_chained_log_file(args.create_sample_log)
        if not args.log_file:
            args.log_file = args.create_sample_log

    if not args.log_file:
        parser.print_help()
        sys.exit(2)

    verifier = ImmutableLogVerifier(args.log_file)
    report = verifier.verify_integrity()
    out_json = args.output_dir / f"{args.log_file.stem}_integrity.json"
    verifier.export_json(report, out_json)

    if report.is_integrity_intact:
        print(f"[+] Log integrity VERIFIED. Merkle Root: {report.merkle_root_hash}")
        sys.exit(0)
    else:
        print(f"[!] Log TAMPERING detected at line {report.chain_broken_at_line}!")
        sys.exit(1)


if __name__ == "__main__":
    main()

