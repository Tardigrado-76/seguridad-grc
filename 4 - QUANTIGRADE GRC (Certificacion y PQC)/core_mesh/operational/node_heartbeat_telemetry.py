#!/usr/bin/env python3
"""
node_heartbeat_telemetry.py — CTEM Telemetry: HMAC-SHA256 Authenticated Node Health & Status Beacons.
Aligns with:
 - ENS RD 311/2022: Medida [op.mon.1] Monitorización del Sistema
 - NIS2 Directiva UE 2022/2555: Art. 21.2(c) Continuidad de las operaciones y monitorización
 - CWE-20: Improper Input Validation
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import logging
import os
import secrets
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.Heartbeat")


class NodeHeartbeatTelemetry:
    """Generates and verifies cryptographic health heartbeats for audit nodes and mesh agents."""

    def __init__(self, node_id: str, secret_key: bytes | None = None):
        self.node_id = node_id
        env_secret = os.environ.get("QG_HMAC_SECRET")
        if secret_key:
            self.secret = secret_key
        elif env_secret:
            self.secret = env_secret.encode("utf-8")
        else:
            # Ephemeral deterministic fallback for local testing
            self.secret = b"QG_EPHEMERAL_DEFAULT_HMAC_KEY_SECURE_256"

        self._seen_nonces: set[str] = set()

    def generate_heartbeat(self, status: str = "HEALTHY", active_tasks: int = 0) -> dict[str, Any]:
        """Creates an authenticated heartbeat beacon."""
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        nonce = secrets.token_hex(8)

        payload_str = f"{self.node_id}:{status}:{active_tasks}:{ts}:{nonce}"
        sig = hmac.new(self.secret, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()

        return {
            "node_id": self.node_id,
            "status": status,
            "active_tasks": active_tasks,
            "timestamp": ts,
            "nonce": nonce,
            "hmac_sha256": sig
        }

    def verify_heartbeat(self, beacon: dict[str, Any], max_drift_seconds: int = 60) -> bool:
        """Verifies integrity, authenticity, and freshness of a received heartbeat beacon."""
        try:
            node_id = beacon["node_id"]
            status = beacon["status"]
            active_tasks = beacon["active_tasks"]
            ts = beacon["timestamp"]
            nonce = beacon["nonce"]
            sig = beacon["hmac_sha256"]

            # Anti-replay check
            if nonce in self._seen_nonces:
                logger.warning("Replay attack detected: duplicate nonce %s", nonce)
                return False

            # Drift / freshness check
            beacon_dt = datetime.datetime.fromisoformat(ts)
            now = datetime.datetime.now(datetime.timezone.utc)
            drift = abs((now - beacon_dt).total_seconds())
            if drift > max_drift_seconds:
                logger.warning("Expired heartbeat: drift %.1fs > %ds", drift, max_drift_seconds)
                return False

            # Verify signature
            payload_str = f"{node_id}:{status}:{active_tasks}:{ts}:{nonce}"
            expected_sig = hmac.new(self.secret, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()

            if not hmac.compare_digest(sig, expected_sig):
                logger.warning("Invalid HMAC signature on heartbeat from %s", node_id)
                return False

            self._seen_nonces.add(nonce)
            # Cap seen set size
            if len(self._seen_nonces) > 5000:
                self._seen_nonces.clear()
            return True
        except Exception as e:
            logger.error("Error verifying heartbeat beacon: %s", e)
            return False

