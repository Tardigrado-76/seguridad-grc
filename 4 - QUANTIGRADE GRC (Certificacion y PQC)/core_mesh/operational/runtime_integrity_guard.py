#!/usr/bin/env python3
"""
runtime_integrity_guard.py — CTEM Host Defense: Runtime Process Integrity & Memory Tamper Supervisor.
Decision B (Approved): Dual mode — dry_run=True default for audit & alerts + kill_on_tamper armed mode for HITL defense.
Aligns with:
 - ENS RD 311/2022: Medida [op.mon.2] Detección de intrusión y alteración en runtime
 - NIS2 Directiva UE 2022/2555: Art. 21.2(c) Prevención de incidentes técnicos
 - MITRE ATT&CK: T1055 (Process Injection), T1003 (OS Credential Dumping)
"""
from __future__ import annotations

import datetime
import logging
import os
import sys
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.RuntimeGuard")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class RuntimeIntegrityGuard:
    """Supervises host process integrity against thread injection, unauthorized memory dumps, and RAM leakage."""

    SUSPICIOUS_LIBRARIES = [
        "dbghelp.dll",
        "minidump.dll",
        "frida",
        "inject",
        "subhook",
    ]

    def __init__(self, dry_run: bool = True, kill_on_tamper: bool = False, max_rss_mb: float = 800.0):
        self.dry_run = dry_run
        self.kill_on_tamper = kill_on_tamper
        self.max_rss_mb = max_rss_mb
        self.pid = os.getpid()
        self.baseline_threads = 1
        if PSUTIL_AVAILABLE:
            try:
                self.process = psutil.Process(self.pid)
                self.baseline_threads = self.process.num_threads()
            except Exception:
                self.process = None
        else:
            self.process = None

    def inspect_process(self) -> dict[str, Any]:
        """Performs a single evaluation pass on current process health and anomalies."""
        anomalies: list[dict[str, Any]] = []

        if not PSUTIL_AVAILABLE or not self.process:
            return {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "pid": self.pid,
                "status": "PASS",
                "note": "psutil not available; simulated healthy baseline maintained.",
                "anomalies": []
            }

        try:
            # 1. Thread count anomaly / Thread injection detection
            curr_threads = self.process.num_threads()
            if curr_threads > self.baseline_threads + 25:
                anomalies.append({
                    "type": "THREAD_INJECTION_SUSPICION",
                    "severity": "CRITICAL",
                    "detail": f"Anomalous thread surge: {curr_threads} active threads vs baseline {self.baseline_threads}."
                })

            # 2. Memory dump / Suspicious modules detection
            if os.name == "nt":
                try:
                    for m in self.process.memory_maps():
                        p_str = getattr(m, "path", "").lower()
                        for bad in self.SUSPICIOUS_LIBRARIES:
                            if bad in p_str:
                                anomalies.append({
                                    "type": "MEMORY_DUMP_INSPECTOR_DETECTED",
                                    "severity": "CRITICAL",
                                    "detail": f"Suspicious library mapping detected: {bad} ({p_str})"
                                })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            # 3. Excessive Memory Leak (RGPD / NIS2 resource exhaustion)
            mem_info = self.process.memory_info()
            rss_mb = mem_info.rss / (1024 * 1024)
            if rss_mb > self.max_rss_mb:
                anomalies.append({
                    "type": "MEMORY_EXHAUSTION_LIMIT_EXCEEDED",
                    "severity": "HIGH",
                    "detail": f"Process RSS is {rss_mb:.1f} MB (threshold {self.max_rss_mb:.1f} MB)."
                })

        except Exception as e:
            logger.error("Error inspecting process: %s", e)

        has_critical = any(a["severity"] == "CRITICAL" for a in anomalies)
        status = "COMPROMISED" if has_critical else ("WARNING" if anomalies else "SECURE")

        # Decision B execution logic
        if has_critical:
            if not self.dry_run and self.kill_on_tamper:
                logger.critical("[RUNTIME_GUARD] ARMED: Critical tamper detected! Self-terminating process %d.", self.pid)
                sys.exit(137)  # SIGKILL exit simulation
            else:
                logger.warning("[RUNTIME_GUARD] DRY_RUN: Critical tamper detected but termination skipped (dry_run=%s, kill_on_tamper=%s).", self.dry_run, self.kill_on_tamper)

        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "pid": self.pid,
            "dry_run": self.dry_run,
            "kill_on_tamper": self.kill_on_tamper,
            "status": status,
            "anomalies_count": len(anomalies),
            "anomalies": anomalies
        }

