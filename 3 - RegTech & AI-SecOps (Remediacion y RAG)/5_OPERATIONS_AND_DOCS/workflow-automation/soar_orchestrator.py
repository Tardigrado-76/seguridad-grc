import json
import logging
import os
import urllib.request

from src.bunker_event_bus import (
    EVENT_HONEYPOT_ALERT,
    EVENT_VM_DETECTED,
    EVENT_WATCHDOG_CRITICAL,
    BunkerEventBus,
)
from src.bunker_logger import log_auditoria

logger = logging.getLogger("BunkerOS.SOAR")


class BunkerSOAROrchestrator:
    """Security Orchestration, Automation, and Response (SOAR).
    Escucha eventos del bus y reacciona de forma autónoma.
    """

    def __init__(self) -> None:
        import threading

        self.bus = BunkerEventBus.get_instance()
        self.webhook_url = os.getenv(
            "SOAR_WEBHOOK_URL", "https://soar.bunker.local/api/v1/alerts",
        )

        self.bus.subscribe(EVENT_HONEYPOT_ALERT, self._handle_honeypot)
        self.bus.subscribe(EVENT_VM_DETECTED, self._handle_vm_detection)
        self.bus.subscribe(EVENT_WATCHDOG_CRITICAL, self._handle_critical)
        self.bus.subscribe(
            "LLM_INJECTION_ATTEMPT", self._handle_sliding_window_alert,
        )
        self.bus.subscribe(
            "RATE_LIMIT_EXCEEDED", self._handle_sliding_window_alert,
        )

        self.alert_timestamps = []
        self._lock = threading.Lock()

        logger.info(
            "[SOAR] Orquestador inicializado y suscrito a eventos críticos.",
        )

    def _handle_sliding_window_alert(self, event: dict) -> None:
        import time

        now = time.time()
        with self._lock:
            self.alert_timestamps.append(now)
            self.alert_timestamps = [
                t for t in self.alert_timestamps if now - t <= 30.0
            ]
            if len(self.alert_timestamps) >= 5:
                logger.critical(
                    f"[SOAR] Sliding window threshold reached: {
                        len(
                            self.alert_timestamps)} alerts in 30s! Triggering Auto-Air-Gap.",
                )
                self._simulate_network_isolation()
                try:
                    from src.bunker_logger import _execute_network_lockdown

                    _execute_network_lockdown(
                        reason="Auto-Air-Gap: 5+ attacks in 30s",
                    )
                except (ValueError, TypeError, RuntimeError, OSError) as e:
                    logger.exception(
                        f"[SOAR] Failed to execute network lockdown: {e}",
                    )

    def _trigger_webhook(self, title: str, severity: str, details: dict) -> None:
        try:
            payload = json.dumps(
                {"title": title, "severity": severity, "details": details},
            ).encode("utf-8")

            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            if self.webhook_url.lower().startswith("http"):
                urllib.request.urlopen(req, timeout=5)  # nosec B310
        except (ValueError, TypeError, RuntimeError, OSError) as e:
            logger.exception(
                f"[SOAR] Falla al enviar Webhook al SOAR corporativo: {e}",
            )

    def _simulate_network_isolation(self) -> None:
        """Bloquea dinámicamente conexiones (simulación de firewall)."""
        logger.critical(
            "[SOAR] Ejecutando aislamiento de red activo (Network Isolation).",
        )
        log_auditoria(
            "SYSTEM",
            "NETWORK_ISOLATION",
            "SOAR Orquestador activó contención de red.",
        )

    def _handle_honeypot(self, event: dict) -> None:
        payload = event.get("payload", {})
        logger.warning(f"[SOAR] Mitigando alerta XDR/Honeypot: {payload}")
        self._trigger_webhook("XDR Honeypot Alert", "HIGH", payload)
        self._simulate_network_isolation()

    def _handle_vm_detection(self, event: dict) -> None:
        logger.critical(
            "[SOAR] Intrusión VM Hostil Detectada. Posible Clonación.",
        )
        self._trigger_webhook(
            "Hostile VM Detected", "CRITICAL", event.get("payload", {}),
        )

        # En una situación real esto podría lanzar el suicidio digital:
        # from src.bunker_digital_suicide import execute_digital_suicide
        # execute_digital_suicide(reason="VM Detection SOAR Trigger")

    def _handle_critical(self, event: dict) -> None:
        logger.critical(f"[SOAR] Evento Watchdog Crítico: {
                event.get('payload')}")
        self._trigger_webhook(
            "Watchdog Critical Alert", "CRITICAL", event.get("payload", {}),
        )


def init_soar() -> None:
    # Instancia el SOAR para que se suscriba al bus
    BunkerSOAROrchestrator()
