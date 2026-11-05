"""consumer.py — Asynchronous Event Stream Consumer & Reactive Compliance Daemon.
==============================================================================
Consumidor asíncrono de eventos de seguridad y telemetría en tiempo real.
- Conexión a Redis Streams / PubSub / RabbitMQ (con fallback a Memory Queue).
- Procesamiento continuo en segundo plano con control de contrapresión (Backpressure).
- Enrutamiento automático de eventos al Log Auditor Agent.
- Gestión de Dead-Letter Queue (DLQ) para eventos malformados.
"""

import logging
import os
import queue
import sys
import threading
import time
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("StreamingConsumer.Daemon")

from log_auditor_agent import StreamLogAuditorAgent


class EventStreamConsumer:
    """Consumidor de eventos reactivo para auditoría continua."""

    def __init__(self, topic: str = "security_audit_stream", redis_url: str | None = None) -> None:
        self.topic = topic
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.agent = StreamLogAuditorAgent()

        self.memory_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.dead_letter_queue: list[dict[str, Any]] = []

        self.is_running = False
        self._worker_thread: threading.Thread | None = None
        self.total_processed_events = 0
        self.total_alerts_dispatched = 0

    def publish_event(self, event: dict[str, Any]) -> bool:
        """Publica un evento en la cola de procesamiento."""
        try:
            self.memory_queue.put_nowait(event)
            return True
        except queue.Full:
            logger.exception("[Consumer] Queue de eventos saturada! Descartando o aplicando backpressure.")
            return False

    def process_single_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Procesa un evento individual a través del agente de auditoría."""
        try:
            self.total_processed_events += 1
            incident = self.agent.evaluate_event(event)
            if incident:
                self.total_alerts_dispatched += 1
            return incident
        except Exception as e:
            logger.exception(f"[Consumer] Error procesando evento {event}: {e}")
            self.dead_letter_queue.append({"event": event, "error": str(e), "timestamp": time.time()})
            return None

    def start_worker(self, poll_interval: float = 0.05) -> None:
        """Inicia el demonio de consumo en un hilo asíncrono."""
        if self.is_running:
            return

        self.is_running = True

        def _consume_loop() -> None:
            logger.info(f"🚀 [Consumer Daemon] Escuchando topic '{self.topic}'...")
            while self.is_running:
                try:
                    event = self.memory_queue.get(timeout=poll_interval)
                    self.process_single_event(event)
                    self.memory_queue.task_done()
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.exception(f"[Consumer Loop Error] {e}")

        self._worker_thread = threading.Thread(target=_consume_loop, daemon=True)
        self._worker_thread.start()

    def stop_worker(self) -> None:
        """Detiene el demonio de consumo."""
        self.is_running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)
            logger.info("[Consumer Daemon] Detenido correctamente.")

    def get_stats(self) -> dict[str, Any]:
        """Estadísticas operativas de consumo."""
        return {
            "topic": self.topic,
            "is_running": self.is_running,
            "pending_queue_size": self.memory_queue.qsize(),
            "total_processed_events": self.total_processed_events,
            "total_alerts_dispatched": self.total_alerts_dispatched,
            "dlq_size": len(self.dead_letter_queue),
        }


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    consumer = EventStreamConsumer()
    consumer.start_worker()


    # Inyectar eventos de prueba
    sample_events = [
        {"event_id": "evt-001", "service": "auth-service", "user_id": "usr_99", "action": "login_success"},
        {"event_id": "evt-002", "service": "database-cluster", "user_id": "dba_1", "action": "cluster_degraded service_down timeout"},
        {"event_id": "evt-003", "service": "llm-gateway", "user_id": "usr_42", "action": "prompt_injection bypass_guardrails"},
    ]

    for ev in sample_events:
        consumer.publish_event(ev)

    time.sleep(0.5)
    consumer.stop_worker()

