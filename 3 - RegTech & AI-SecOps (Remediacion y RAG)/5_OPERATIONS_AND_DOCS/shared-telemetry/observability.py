"""BunkerOS — OpenTelemetry Security & LLMOps Metrics Instrumentation.
==================================================================
Integración con FastAPI y RAG Engines para exportar métricas de seguridad y LLMOps.
Cumplimiento: ENS Alta op.mon.1, NIS2 Art.21, NIST 800-53 SI-4, EU AI Act Art. 12 (Logging & Traceability)
"""

import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Optional

logger = logging.getLogger("BunkerOS.Observability")

# Conditional import — graceful degradation if OTel not installed
try:
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import Tracer

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    logger.warning("[Observability] OpenTelemetry SDK not installed. Telemetry in fallback mode.")


class BunkerSecurityMetrics:
    """Singleton para métricas de seguridad instrumentadas vía OpenTelemetry.

    Métricas exportadas:
    - bunkeros.auth.failures: Contador de fallos de autenticación
    - bunkeros.jwt.rejects: Contador de tokens JWT rechazados (WASM + backend)
    - bunkeros.wasm.errors: Errores en la validación WASM
    - bunkeros.redis.failures: Fallos de conexión/operación Redis
    - bunkeros.supply_chain.events: Eventos de seguridad de supply chain
    - bunkeros.rate_limit.hits: IPs que alcanzan el rate limit
    - bunkeros.audit.entries: Entradas de auditoría generadas
    """

    _instance: Optional["BunkerSecurityMetrics"] = None

    def __init__(self) -> None:
        self._initialized = False

        if not OTEL_AVAILABLE:
            return

        try:
            resource = Resource.create(
                {
                    "service.name": "bunkeros",
                    "service.version": "4.2.0",
                    "deployment.environment": os.getenv("BUNKER_ENV", "production"),
                },
            )

            endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317")
            exporter = OTLPMetricExporter(endpoint=endpoint, insecure=True)
            reader = PeriodicExportingMetricReader(exporter, export_interval_millis=15000)
            provider = MeterProvider(resource=resource, metric_readers=[reader])
            metrics.set_meter_provider(provider)

            meter = metrics.get_meter("bunkeros.security", "1.0.0")

            # ── Security Counters ──
            self.auth_failures = meter.create_counter(
                "bunkeros.auth.failures",
                description="Authentication failures (login, JWT validation)",
                unit="1",
            )
            self.jwt_rejects = meter.create_counter(
                "bunkeros.jwt.rejects",
                description="JWT tokens rejected by WASM or backend validation",
                unit="1",
            )
            self.wasm_errors = meter.create_counter(
                "bunkeros.wasm.errors",
                description="WASM module validation errors",
                unit="1",
            )
            self.redis_failures = meter.create_counter(
                "bunkeros.redis.failures",
                description="Redis connection or operation failures",
                unit="1",
            )
            self.supply_chain_events = meter.create_counter(
                "bunkeros.supply_chain.events",
                description="Supply chain security events (SRI mismatch, etc.)",
                unit="1",
            )
            self.rate_limit_hits = meter.create_counter(
                "bunkeros.rate_limit.hits",
                description="Rate limit threshold reached",
                unit="1",
            )
            self.audit_entries = meter.create_counter(
                "bunkeros.audit.entries",
                description="Audit log entries generated",
                unit="1",
            )

            # ── Gauges ──
            self.active_sessions = meter.create_up_down_counter(
                "bunkeros.sessions.active",
                description="Currently active authenticated sessions",
                unit="1",
            )

            self._initialized = True
            logger.info("[Observability] OpenTelemetry security metrics initialized.")

        except (ValueError, TypeError, RuntimeError, OSError) as e:
            logger.exception(f"[Observability] Failed to initialize OTel: {e}")

    @classmethod
    def get_instance(cls) -> "BunkerSecurityMetrics":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def record_auth_failure(self, reason: str = "unknown") -> None:
        if self._initialized:
            self.auth_failures.add(1, {"reason": reason})

    def record_jwt_reject(self, reason: str = "unknown") -> None:
        if self._initialized:
            self.jwt_rejects.add(1, {"reason": reason})

    def record_wasm_error(self, error_type: str = "unknown") -> None:
        if self._initialized:
            self.wasm_errors.add(1, {"error_type": error_type})

    def record_redis_failure(self, operation: str = "unknown") -> None:
        if self._initialized:
            self.redis_failures.add(1, {"operation": operation})

    def record_rate_limit(self, ip: str = "unknown") -> None:
        if self._initialized:
            self.rate_limit_hits.add(1, {"source_ip_hash": ip[:8]})

    def record_audit_entry(self, action: str = "unknown") -> None:
        if self._initialized:
            self.audit_entries.add(1, {"action": action})


class LLMOpsTracer:
    """Instrumentación de LLMOps Enterprise y Trazabilidad de Inferencia IA.
    Captura latencias, tokens, costos estimados, calidad de recuperación y alucinaciones.
    Compatible con Phoenix (Arize), LangSmith y OpenTelemetry Tracing.
    """

    _instance: Optional["LLMOpsTracer"] = None

    def __init__(self) -> None:
        self._initialized = False
        self.tracer: Any | None = None
        self.traces_buffer: list[dict[str, Any]] = []
        self.max_buffer_size = 500

        if OTEL_AVAILABLE:
            try:
                self.tracer = trace.get_tracer("bunkeros.llmops", "1.0.0")
                meter = metrics.get_meter("bunkeros.llmops", "1.0.0")

                # Metrics
                self.llm_calls = meter.create_counter(
                    "llmops.calls.total",
                    description="Total LLM execution calls",
                    unit="1",
                )
                self.prompt_tokens = meter.create_counter(
                    "llmops.tokens.prompt",
                    description="Total prompt tokens processed",
                    unit="1",
                )
                self.completion_tokens = meter.create_counter(
                    "llmops.tokens.completion",
                    description="Total completion tokens generated",
                    unit="1",
                )
                self.latency_histogram = meter.create_histogram(
                    "llmops.latency.seconds",
                    description="LLM execution duration in seconds",
                    unit="s",
                )
                self.estimated_cost_counter = meter.create_counter(
                    "llmops.cost.usd",
                    description="Estimated total inference cost in USD",
                    unit="USD",
                )
                self.hallucination_counter = meter.create_counter(
                    "llmops.hallucinations.detected",
                    description="Detected hallucination count in RAG answers",
                    unit="1",
                )
                self._initialized = True
                logger.info("[LLMOpsTracer] OpenTelemetry LLMOps metrics and tracer initialized.")
            except Exception as e:
                logger.warning(f"[LLMOpsTracer] Initialization error: {e}")

    @classmethod
    def get_instance(cls) -> "LLMOpsTracer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @contextmanager
    def start_span(self, span_name: str, attributes: dict[str, Any] | None = None):
        """Context manager para trazas de ejecución de componentes de IA."""
        start_time = time.time()
        span_attrs = attributes or {}
        span_obj = None

        if self.tracer:
            try:
                span_obj = self.tracer.start_span(span_name)
                for k, v in span_attrs.items():
                    span_obj.set_attribute(str(k), str(v))
            except Exception as e:
                logger.debug(f"[LLMOpsTracer] Failed to start OTel span: {e}")

        try:
            yield span_obj
        finally:
            duration = time.time() - start_time
            if span_obj:
                try:
                    span_obj.set_attribute("duration_sec", duration)
                    span_obj.end()
                except Exception:
                    pass

    def record_llm_execution(
        self,
        model_name: str,
        engine_type: str,
        prompt_tokens: int,
        completion_tokens: int,
        duration_sec: float,
        cost_usd: float = 0.0,
        hallucination_detected: bool = False,
        extra_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Registra métricas y guarda traza estructurada de ejecución de LLM."""
        trace_record = {
            "timestamp": time.time(),
            "model_name": model_name,
            "engine_type": engine_type,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "duration_sec": duration_sec,
            "cost_usd": cost_usd,
            "hallucination_detected": hallucination_detected,
            "metadata": extra_metadata or {},
        }

        # Guardar en buffer en memoria para dashboard / debugging local
        self.traces_buffer.append(trace_record)
        if len(self.traces_buffer) > self.max_buffer_size:
            self.traces_buffer.pop(0)

        # Enviar a OpenTelemetry si está activo
        if self._initialized:
            try:
                attrs = {"model": model_name, "engine": engine_type}
                self.llm_calls.add(1, attrs)
                self.prompt_tokens.add(prompt_tokens, attrs)
                self.completion_tokens.add(completion_tokens, attrs)
                self.latency_histogram.record(duration_sec, attrs)
                if cost_usd > 0:
                    self.estimated_cost_counter.add(cost_usd, attrs)
                if hallucination_detected:
                    self.hallucination_counter.add(1, attrs)
            except Exception as e:
                logger.debug(f"[LLMOpsTracer] Error recording metrics: {e}")

        logger.info(
            f"[LLMOps] Engine={engine_type} Model={model_name} Tokens={prompt_tokens}+{completion_tokens} "
            f"Latency={duration_sec:.2f}s Cost=${cost_usd:.5f}",
        )
        return trace_record

    def get_recent_traces(self, limit: int = 50) -> list[dict[str, Any]]:
        """Devuelve las trazas recientes para inspección."""
        return self.traces_buffer[-limit:]

    def get_aggregated_stats(self) -> dict[str, Any]:
        """Calcula estadísticas agregadas para FinOps y Dashboards."""
        if not self.traces_buffer:
            return {
                "total_calls": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "avg_latency_sec": 0.0,
                "hallucination_rate": 0.0,
            }

        total_calls = len(self.traces_buffer)
        total_tokens = sum(t["total_tokens"] for t in self.traces_buffer)
        total_cost = sum(t["cost_usd"] for t in self.traces_buffer)
        avg_latency = sum(t["duration_sec"] for t in self.traces_buffer) / total_calls
        hallucinations = sum(1 for t in self.traces_buffer if t["hallucination_detected"])

        return {
            "total_calls": total_calls,
            "total_tokens": total_tokens,
            "total_cost_usd": round(total_cost, 6),
            "avg_latency_sec": round(avg_latency, 3),
            "hallucination_rate": round(hallucinations / total_calls, 4),
        }
