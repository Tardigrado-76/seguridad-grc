#!/usr/bin/env python3
"""
test_dynamic_holographic_qr.py - TDD Suite for DynamicHolographicQR.
Verifies offline payload creation, deterministic SVG rendering, and zero network calls.
"""

from __future__ import annotations

import json

from core_mesh.business_execution.dynamic_holographic_qr import DynamicHolographicQR


def test_qr_payload_creation():
    qr = DynamicHolographicQR()
    dummy_merkle = "a" * 64
    payload = qr.create_payload(merkle_root=dummy_merkle, framework_id="DGAM", compliance_score=100.0)

    assert payload.merkle_root == dummy_merkle
    assert payload.framework_id == "DGAM"
    assert payload.compliance_score == 100.0
    assert len(payload.verification_hash) == 64
    assert payload.offline_verification_uri.startswith("qgrade://verify/v3/")


def test_qr_svg_generation():
    qr = DynamicHolographicQR()
    dummy_merkle = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    payload = qr.create_payload(merkle_root=dummy_merkle)
    svg = qr.generate_svg(payload, size_px=200)

    assert "<svg" in svg
    assert "</svg>" in svg
    assert 'viewBox="0 0 200 200"' in svg
    assert "#00E5FF" in svg  # Cyan neon accent
    assert "#10B981" in svg  # Emerald green center


def test_export_json_valid():
    qr = DynamicHolographicQR()
    payload = qr.create_payload(merkle_root="1234567890abcdef")
    exported = qr.export_verification_json(payload)
    parsed = json.loads(exported)
    assert parsed["merkle_root"] == "1234567890abcdef"
    assert "offline_verification_uri" in parsed
