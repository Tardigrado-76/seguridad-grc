#!/usr/bin/env python3
"""
test_airgap_armor.py - TDD Suite for AirGapArmorSentinel.
Verifies ZERO-MOCK socket interception, loopback allowance, external call detection, and fail-closed blocking.
"""

from __future__ import annotations

import socket
import threading

import pytest

from core_mesh.operational.airgap_armor import (
    AirGapArmorSentinel,
    AirGapEnclaveViolationError,
)


@pytest.fixture(autouse=True)
def clean_sentinel():
    """Ensures sentinel is clean and reset for each test."""
    sentinel = AirGapArmorSentinel(enforce_fail_closed=True)
    sentinel.reset()
    yield sentinel
    sentinel.stop_monitoring()


def test_sentinel_initial_state(clean_sentinel: AirGapArmorSentinel):
    clean_sentinel.start_monitoring()
    telemetry = clean_sentinel.get_telemetry()
    assert telemetry.armor_active is True
    assert telemetry.outbound_calls_count == 0
    assert telemetry.status == "ARMOR_ACTIVE_100_AIRGAPPED"
    assert telemetry.monitoring_active is True
    assert len(telemetry.violations) == 0


def test_sentinel_permits_local_loopback(clean_sentinel: AirGapArmorSentinel):
    clean_sentinel.start_monitoring()

    # Start a dummy local TCP server on loopback
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_one():
        try:
            conn, _ = server.accept()
            conn.close()
        except OSError:
            pass

    t = threading.Thread(target=accept_one, daemon=True)
    t.start()

    # Connect client on loopback
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    client.close()
    server.close()

    telemetry = clean_sentinel.get_telemetry()
    # Loopback does not count as outbound external call
    assert telemetry.armor_active is True
    assert telemetry.outbound_calls_count == 0
    assert len(telemetry.violations) == 0


def test_sentinel_blocks_external_call_in_fail_closed(clean_sentinel: AirGapArmorSentinel):
    clean_sentinel.enforce_fail_closed = True
    clean_sentinel.start_monitoring()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(AirGapEnclaveViolationError) as exc_info:
        # Attempt connection to public DNS IP (non-loopback)
        sock.connect(("8.8.8.8", 53))

    assert "Outbound network connection blocked to 8.8.8.8:53" in str(exc_info.value)

    telemetry = clean_sentinel.get_telemetry()
    assert telemetry.armor_active is False
    assert telemetry.outbound_calls_count == 1
    assert telemetry.status == "ARMOR_BREACHED_OUTBOUND_DETECTED"
    assert len(telemetry.violations) == 1
    assert telemetry.violations[0]["target_host"] == "8.8.8.8"
    assert telemetry.violations[0]["blocked"] is True


def test_sentinel_logs_external_call_in_monitor_mode(clean_sentinel: AirGapArmorSentinel):
    clean_sentinel.enforce_fail_closed = False
    clean_sentinel.start_monitoring()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Target unreachable port on reserved documentation IP (RFC 5737) to avoid actual open connection
    try:
        sock.settimeout(0.01)
        sock.connect(("192.0.2.1", 9999))
    except (TimeoutError, OSError):
        pass
    finally:
        sock.close()

    telemetry = clean_sentinel.get_telemetry()
    assert telemetry.armor_active is False
    assert telemetry.outbound_calls_count >= 1
    assert telemetry.status == "ARMOR_BREACHED_OUTBOUND_DETECTED"
    assert len(telemetry.violations) >= 1
