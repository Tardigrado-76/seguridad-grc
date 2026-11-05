#!/usr/bin/env python3
"""
test_ens_fim_integrity.py
TDD Suite for ENS RD 311/2022 [op.exp.7] File Integrity Monitoring (FIM)
and signed JSON manifest validation.
"""

import json
import sys
from pathlib import Path

# Ensure local engines path is included
engines_dir = Path(__file__).resolve().parent.parent / "engines"
if str(engines_dir) not in sys.path:
    sys.path.insert(0, str(engines_dir))

def test_ens_fim_monitor_lifecycle(tmp_path):
    """Verify FIM manifest creation, SHA-256 signing, and tamper detection."""
    from ens_fim_file_integrity_monitor import ENSFIMMonitor

    # Create dummy critical files
    crit_dir = tmp_path / "bin"
    crit_dir.mkdir()
    f1 = crit_dir / "service_core.sys"
    f1.write_text("BINARY_BYTECODE_VERSION_1", encoding="utf-8")
    f2 = crit_dir / "security_policy.conf"
    f2.write_text("TLS_STRICT=1\nMFA=1", encoding="utf-8")

    manifest_path = tmp_path / ".integrity_manifest.json"
    monitor = ENSFIMMonitor(manifest_path=manifest_path)

    # 1. Baseline generation and signed manifest creation
    manifest = monitor.generate_baseline([crit_dir])
    assert manifest_path.exists()
    assert "signature_sha256" in manifest
    assert "files" in manifest
    assert len(manifest["files"]) == 2

    # 2. Validation with unchanged files must pass with zero violations
    verification = monitor.verify_integrity(crit_dir)
    assert verification.is_valid is True
    assert len(verification.tampered_files) == 0

    # 3. Simulate unauthorized tampering of a file
    f1.write_text("TAMPERED_BYTECODE_BACKDOOR", encoding="utf-8")
    verification_tampered = monitor.verify_integrity(crit_dir)
    assert verification_tampered.is_valid is False
    assert any("service_core.sys" in f for f in verification_tampered.tampered_files)

    # 4. Simulate tampering with the manifest itself (signature mismatch)
    with open(manifest_path, "r", encoding="utf-8") as fp:
        raw_manifest = json.load(fp)
    raw_manifest["signature_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
    with open(manifest_path, "w", encoding="utf-8") as fp:
        json.dump(raw_manifest, fp)

    verification_sig = monitor.verify_integrity(crit_dir)
    assert verification_sig.is_valid is False
    assert verification_sig.manifest_signature_valid is False
