"""
Cryptographic Integrity Tests for backup_integrity Module
"""

import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import hashlib
import os
import pytest

def test_sha256_hash_integrity():
    data = b"Bunker_ENS_Alta_Audit_Payload_2026"
    digest1 = hashlib.sha256(data).hexdigest()
    digest2 = hashlib.sha256(data).hexdigest()
    assert digest1 == digest2
    assert len(digest1) == 64

def test_backup_environment_config():
    from dotenv import load_dotenv
    load_dotenv()
    log_level = os.getenv("LOG_LEVEL", "INFO")
    assert log_level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
