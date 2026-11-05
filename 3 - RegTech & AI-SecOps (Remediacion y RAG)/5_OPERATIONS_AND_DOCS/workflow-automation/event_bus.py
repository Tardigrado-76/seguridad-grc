"""bunker_event_bus.py — BunkerOS Cognitive Orchestration EventBus (IPC).
=====================================================================
Singleton Pub/Sub EventBus based on multiprocessing.managers.BaseManager.
Enables real-time event propagation between Watchdog, Honeypot, Key Validator,
Anti-VM, and Digital Suicide subsystems.

Compliance: ENS Alta op.mon.1, NIS2 Art.21 (incident handling), CRA Art.13.
"""

import logging
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from multiprocessing.managers import BaseManager
from typing import Optional

logger = logging.getLogger("BunkerOS.EventBus")

# ─── Event Type Constants ───────────────────────────────────────────────
EVENT_HONEYPOT_ALERT = "HONEYPOT_ALERT"
EVENT_WATCHDOG_WARNING = "WATCHDOG_WARNING"
EVENT_WATCHDOG_CRITICAL = "WATCHDOG_CRITICAL"
EVENT_USB_DISCONNECTED = "USB_DISCONNECTED"
EVENT_USB_VALIDATED = "USB_VALIDATED"
EVENT_VM_DETECTED = "VM_DETECTED"
EVENT_LOCKDOWN = "LOCKDOWN"
EVENT_DIGITAL_SUICIDE = "DIGITAL_SUICIDE"
EVENT_HEALTH_OK = "HEALTH_OK"

# ─── Shared Event Store (thread-safe, manager-hosted) ───────────────────


class _EventStore:
    """Thread-safe event store accessible via BaseManager proxy.
    Stores events in a bounded list and tracks subscriber read positions.
    """

    def __init__(self, max_events: int = 5000) -> None:
        self._events: list[dict] = []
        self._lock = threading.RLock()
        self._max_events = max_events
        self._subscribers: dict[str, int] = {}

    def publish(
        self, event_type: str, payload: dict, source: str = "UNKNOWN",
    ) -> str:
        """Publish an event. Returns the event correlation ID."""
        correlation_id = str(uuid.uuid4())
        event = {
            "correlation_id": correlation_id,
            "event_type": event_type,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": dict(payload),
        }
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max_events:
                trim = len(self._events) - self._max_events
                self._events = self._events[trim:]
                for sid in self._subscribers:
                    self._subscribers[sid] = max(
                        0, self._subscribers[sid] - trim,
                    )
        logger.info(
            f"[EventBus] PUBLISHED {event_type} | CID:{correlation_id} | src:{source}",
        )
        return correlation_id

    def register_subscriber(self, subscriber_id: str) -> None:
        with self._lock:
            self._subscribers[subscriber_id] = len(self._events)

    def poll(self, subscriber_id: str) -> list:
        """Retrieve unread events for a subscriber."""
        with self._lock:
            start = self._subscribers.get(subscriber_id, len(self._events))
            events = list(self._events[start:])
            self._subscribers[subscriber_id] = len(self._events)
            return events

    def get_all_events(self) -> list:
        with self._lock:
            return list(self._events)


# ─── BaseManager Registration ───────────────────────────────────────────

_MANAGER_HOST = "127.0.0.1"
_MANAGER_PORT = 51987
_MANAGER_AUTH = b"BunkerOS_EventBus_Auth_2026"

_global_store = _EventStore()


class BunkerEventBusManager(BaseManager):
    """Cross-process manager hosting the shared EventStore."""


BunkerEventBusManager.register("get_store", callable=lambda: _global_store)


# ─── Singleton EventBus (In-Process + Optional IPC) ─────────────────────


class BunkerEventBus:
    """Singleton EventBus with in-process pub/sub and optional cross-process IPC.

    Usage:
        bus = BunkerEventBus.get_instance()
        bus.subscribe(EVENT_HONEYPOT_ALERT, my_handler)
        bus.publish(EVENT_HONEYPOT_ALERT, {'ip': '10.0.0.1'}, source='Honeypot')
    """

    _instance: Optional["BunkerEventBus"] = None
    _init_lock = threading.Lock()

    def __init__(self) -> None:
        self._local_subscribers: dict[str, list[Callable]] = {}
        self._lock = threading.RLock()
        self._store = _EventStore()
        self._dispatcher_running = False
        self._dispatcher_thread: threading.Thread | None = None

    @classmethod
    def get_instance(cls) -> "BunkerEventBus":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
                    cls._instance._start_dispatcher()
        return cls._instance

    def subscribe(
        self, event_type: str, callback: Callable[[dict], None],
    ) -> None:
        """Register a local callback for an event type."""
        with self._lock:
            if event_type not in self._local_subscribers:
                self._local_subscribers[event_type] = []
            self._local_subscribers[event_type].append(callback)
            logger.info(f"[EventBus] Subscriber registered for {event_type}")

    def publish(
        self, event_type: str, payload: dict, source: str = "UNKNOWN",
    ) -> str:
        """Publish an event and dispatch to local subscribers."""
        cid = self._store.publish(event_type, payload, source)
        self._dispatch_local(
            event_type,
            {
                "correlation_id": cid,
                "event_type": event_type,
                "source": source,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": payload,
            },
        )
        return cid

    def _dispatch_local(self, event_type: str, event: dict) -> None:
        """Dispatch event to all local subscribers for the given type."""
        with self._lock:
            callbacks = list(self._local_subscribers.get(event_type, []))
            wildcard = list(self._local_subscribers.get("*", []))
        for cb in callbacks + wildcard:
            try:
                cb(event)
            except (ValueError, TypeError, RuntimeError, OSError) as e:
                logger.exception(
                    f"[EventBus] Subscriber error on {event_type}: {e}",
                )

    def _start_dispatcher(self) -> None:
        self._dispatcher_running = True

    def shutdown(self) -> None:
        self._dispatcher_running = False
        logger.info("[EventBus] Shutdown complete.")

    def get_event_history(self) -> list:
        return self._store.get_all_events()


# ─── Manager Server (run in orchestrator process) ────────────────────────────


def start_eventbus_server() -> BunkerEventBusManager:
    """Start the BaseManager server for cross-process IPC."""
    manager = BunkerEventBusManager(
        address=(_MANAGER_HOST, _MANAGER_PORT), authkey=_MANAGER_AUTH,
    )
    server = manager.get_server()
    t = threading.Thread(
        target=server.serve_forever, daemon=True, name="EventBusServer",
    )
    t.start()
    logger.info(
        f"[EventBus] IPC Server started on {_MANAGER_HOST}:{_MANAGER_PORT}",
    )
    return manager


def connect_eventbus_client() -> _EventStore | None:
    """Connect to an existing EventBus server from another process."""
    try:
        manager = BunkerEventBusManager(
            address=(_MANAGER_HOST, _MANAGER_PORT), authkey=_MANAGER_AUTH,
        )
        manager.connect()
        return manager.get_store()
    except (ValueError, TypeError, RuntimeError, OSError) as e:
        logger.warning(
            f"[EventBus] Could not connect to IPC server: {e}. Using local bus.",
        )
        return None
