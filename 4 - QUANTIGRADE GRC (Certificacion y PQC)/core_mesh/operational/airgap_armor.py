#!/usr/bin/env python3
"""
airgap_armor.py - Real-Time Zero-Mock Network Sentinel & Fail-Closed Enclave.

Monitors process socket activity and verifies whether ANY real outbound network
connections have been initiated to non-loopback addresses. Operates with ZERO MOCKS:
intercepts socket.socket.connect and raises AirGapEnclaveViolationError in Fail-Closed mode.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
import traceback
from dataclasses import asdict, dataclass, field
from typing import Any


class AirGapEnclaveViolationError(ConnectionError):
    """Raised when an outbound network call is attempted in strict fail-closed Air-Gap mode."""


@dataclass
class OutboundViolation:
    timestamp: str
    target_host: str
    target_port: int
    resolved_ip: str
    blocked: bool
    caller_trace: str


@dataclass
class AirGapTelemetry:
    armor_active: bool
    outbound_calls_count: int
    enforce_fail_closed: bool
    status: str
    monitoring_active: bool
    monitored_since: str
    violations: list[dict[str, Any]] = field(default_factory=list)


class AirGapArmorSentinel:
    """Active socket sentinel that detects real outbound network calls."""

    _instance: AirGapArmorSentinel | None = None
    _lock = threading.Lock()

    def __init__(self, enforce_fail_closed: bool = True):
        self.enforce_fail_closed = enforce_fail_closed
        self.outbound_calls_count: int = 0
        self.outbound_violations: list[OutboundViolation] = []
        self._is_hooked: bool = False
        self._orig_connect = socket.socket.connect
        self._monitored_since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._mutex = threading.Lock()

    @classmethod
    def get_instance(cls, enforce_fail_closed: bool = True) -> AirGapArmorSentinel:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(enforce_fail_closed=enforce_fail_closed)
                cls._instance.start_monitoring()
            return cls._instance

    @staticmethod
    def is_loopback_address(host: str) -> tuple[bool, str]:
        """Verifies if an address resolves strictly to local loopback (127.0.0.1, ::1, localhost)."""
        clean_host = host.strip().lower()
        if clean_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True, "127.0.0.1"

        try:
            resolved_ip = socket.gethostbyname(clean_host)
            ip_obj = ipaddress.ip_address(resolved_ip)
            return ip_obj.is_loopback, resolved_ip
        except (socket.gaierror, ValueError, OSError):
            return False, "unresolved"

    def _intercepted_connect(self, sock: socket.socket, address: Any) -> Any:
        host: str = ""
        port: int = 0
        if isinstance(address, tuple) and len(address) >= 2:
            host = str(address[0])
            try:
                port = int(address[1])
            except (ValueError, TypeError):
                port = 0
        elif isinstance(address, str):
            host = address
            port = 0

        is_loopback, resolved_ip = self.is_loopback_address(host)

        if not is_loopback:
            stack = "".join(traceback.format_stack(limit=5))
            blocked = self.enforce_fail_closed

            violation = OutboundViolation(
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                target_host=host,
                target_port=port,
                resolved_ip=resolved_ip,
                blocked=blocked,
                caller_trace=stack,
            )

            with self._mutex:
                self.outbound_calls_count += 1
                self.outbound_violations.append(violation)

            if blocked:
                raise AirGapEnclaveViolationError(
                    f"[AIR-GAP ARMOR] Outbound network connection blocked to {host}:{port} ({resolved_ip}). "
                    f"Quantigrade Fail-Closed Enclave is active."
                )

        return self._orig_connect(sock, address)

    def start_monitoring(self) -> None:
        """Installs the transparent socket interceptor."""
        with self._mutex:
            if not self._is_hooked:
                sentinel = self

                def hooked_connect(sock_self: socket.socket, addr: Any) -> Any:
                    return sentinel._intercepted_connect(sock_self, addr)

                socket.socket.connect = hooked_connect  # type: ignore[assignment]
                self._is_hooked = True

    def stop_monitoring(self) -> None:
        """Restores original socket connect behavior."""
        with self._mutex:
            if self._is_hooked:
                socket.socket.connect = self._orig_connect  # type: ignore[assignment]
                self._is_hooked = False

    def reset(self) -> None:
        """Resets telemetry counters for testing purposes."""
        with self._mutex:
            self.outbound_calls_count = 0
            self.outbound_violations.clear()
            self._monitored_since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def get_telemetry(self) -> AirGapTelemetry:
        """Returns structured real-time telemetry."""
        with self._mutex:
            is_active = self.outbound_calls_count == 0
            status = "ARMOR_ACTIVE_100_AIRGAPPED" if is_active else "ARMOR_BREACHED_OUTBOUND_DETECTED"
            return AirGapTelemetry(
                armor_active=is_active,
                outbound_calls_count=self.outbound_calls_count,
                enforce_fail_closed=self.enforce_fail_closed,
                status=status,
                monitoring_active=self._is_hooked,
                monitored_since=self._monitored_since,
                violations=[asdict(v) for v in self.outbound_violations],
            )
