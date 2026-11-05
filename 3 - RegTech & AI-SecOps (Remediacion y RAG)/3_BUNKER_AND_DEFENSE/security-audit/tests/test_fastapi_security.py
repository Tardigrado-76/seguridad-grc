"""
Security Audit Suite: test_fastapi_security.py
Validates real DORA Art. 10 cryptographic log immutability and tamper detection.
"""

from pathlib import Path
import pytest
import sys

_AUDIT_DIR = str(Path(__file__).resolve().parent.parent)
if _AUDIT_DIR not in sys.path:
    sys.path.insert(0, _AUDIT_DIR)

from verify_log_immutability import DORALogImmutabilityVerifier, MerkleTreeBuilder


def test_dora_log_immutability_valid_chain(tmp_path):
    """Verify clean chained log passes cryptographic verification with 100% valid lines and Merkle root."""
    log_file = tmp_path / "valid_audit.log"
    DORALogImmutabilityVerifier.create_chained_log_file(log_file, num_entries=5)

    verifier = DORALogImmutabilityVerifier(log_file)
    report = verifier.verify_integrity()

    assert report.total_lines_scanned == 5
    assert report.valid_lines_count == 5
    assert report.tampered_lines_count == 0
    assert report.is_integrity_intact is True
    assert report.dora_compliance_status == "CONFORME_DORA_ART10"
    assert len(report.merkle_root_hash) == 64


def test_dora_log_immutability_tamper_detection(tmp_path):
    """Verify tampered log entry breaks hash chain and is flagged as NO_CONFORME_MODIFICACION_DETECTADA."""
    log_file = tmp_path / "tampered_audit.log"
    DORALogImmutabilityVerifier.create_chained_log_file(log_file, num_entries=5)

    # Tamper with the 3rd line
    lines = log_file.read_text(encoding="utf-8").splitlines()
    parts = lines[2].split(" | ")
    parts[1] = "UNAUTHORIZED_TAMPERED_ACTION payload=INJECTED"
    lines[2] = " | ".join(parts)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = DORALogImmutabilityVerifier(log_file)
    report = verifier.verify_integrity()

    assert report.is_integrity_intact is False
    assert report.dora_compliance_status == "NO_CONFORME_MODIFICACION_DETECTADA"
    assert report.tampered_lines_count > 0
    assert report.chain_broken_at_line == 3
