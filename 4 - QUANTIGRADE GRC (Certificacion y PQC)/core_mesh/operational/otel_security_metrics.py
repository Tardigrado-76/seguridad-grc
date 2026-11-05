#!/usr/bin/env python3
"""
otel_security_metrics.py — CTEM Telemetry: OpenTelemetry & Structured JSON Security Metrics.
Decision A (Approved): Dual mode — Full OpenTelemetry SDK when present + Graceful Structured Fallback.
Aligns with:
 - ENS RD 311/2022: Medida [op.mon.1] Monitorización y Métricas
 - NIS2 Directiva UE 2022/2555: Art. 21 Gestión de incidentes y telemetría
 - NIST SP 800-53: SI-4 Information System Monitoring
 - EU AI Act: Art. 12 Logging & Traceability
"""
from __future__ import annotations

import datetime
import json
import logging
import os
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.Metrics")

# Detect OpenTelemetry SDK availability
try:
    from opentelemetry import metrics
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


class QGSecurityMetrics:
    """Security Metrics instrumented via OpenTelemetry with guaranteed graceful fallback."""

    _instance: QGSecurityMetrics | None = None

    def __new__(cls) -> QGSecurityMetrics:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_metrics()
        return cls._instance

    def _init_metrics(self) -> None:
        self.fallback_counters: dict[str, int] = {
            "auth_failures": 0,
            "jwt_rejects": 0,
            "supply_chain_events": 0,
            "ctem_findings": 0,
            "runtime_anomalies": 0,
            "audit_entries": 0,
        }
        self.event_log: list[dict[str, Any]] = []
        self.otel_enabled = False

        if OTEL_AVAILABLE:
            try:
                res = Resource.create({
                    "service.name": "quantigrade-ctem",
                    "service.version": "4.2.0",
                    "deployment.environment": os.getenv("QG_ENV", "production")
                })
                endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317")
                exporter = OTLPMetricExporter(endpoint=endpoint, insecure=True)
                reader = PeriodicExportingMetricReader(exporter, export_interval_millis=15000)
                provider = MeterProvider(resource=res, metric_readers=[reader])
                metrics.set_meter_provider(provider)
                meter = metrics.get_meter("quantigrade.security", "4.2.0")

                self.otel_counter_auth = meter.create_counter("qg.auth.failures")
                self.otel_counter_findings = meter.create_counter("qg.ctem.findings")
                self.otel_counter_anomalies = meter.create_counter("qg.runtime.anomalies")
                self.otel_counter_audits = meter.create_counter("qg.audit.entries")
                self.otel_enabled = True
                logger.info("OpenTelemetry OTLP metrics initialized successfully.")
            except Exception as e:
                logger.warning("OTel initialization failed (%s), running in fallback mode.", e)
                self.otel_enabled = False
        else:
            logger.info("OpenTelemetry SDK not found. Running in resilient structured fallback mode.")

    def record_auth_failure(self, user_or_node: str, reason: str) -> None:
        self.fallback_counters["auth_failures"] += 1
        record = {
            "type": "AUTH_FAILURE",
            "target": user_or_node,
            "reason": reason,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self.event_log.append(record)
        if self.otel_enabled:
            try:
                self.otel_counter_auth.add(1, {"target": user_or_node, "reason": reason})
            except Exception:
                pass
        logger.warning("[METRICS] Auth Failure: %s", json.dumps(record))

    def record_ctem_finding(self, framework: str, severity: str, rule: str) -> None:
        self.fallback_counters["ctem_findings"] += 1
        record = {
            "type": "CTEM_FINDING",
            "framework": framework,
            "severity": severity,
            "rule": rule,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self.event_log.append(record)
        if self.otel_enabled:
            try:
                self.otel_counter_findings.add(1, {"framework": framework, "severity": severity})
            except Exception:
                pass

    def record_runtime_anomaly(self, anomaly_type: str, details: str) -> None:
        self.fallback_counters["runtime_anomalies"] += 1
        record = {
            "type": "RUNTIME_ANOMALY",
            "anomaly": anomaly_type,
            "details": details,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self.event_log.append(record)
        if self.otel_enabled:
            try:
                self.otel_counter_anomalies.add(1, {"anomaly": anomaly_type})
            except Exception:
                pass
        logger.error("[METRICS] Runtime Anomaly: %s", json.dumps(record))

    def record_audit_entry(self, audit_name: str, status: str) -> None:
        self.fallback_counters["audit_entries"] += 1
        if self.otel_enabled:
            try:
                self.otel_counter_audits.add(1, {"audit": audit_name, "status": status})
            except Exception:
                pass

    def get_snapshot(self) -> dict[str, Any]:
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "otel_active": self.otel_enabled,
            "counters": dict(self.fallback_counters),
            "recent_events_count": len(self.event_log),
            "events_sample": self.event_log[-5:]
        }

