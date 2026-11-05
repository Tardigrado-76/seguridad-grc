from __future__ import annotations
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

class RuntimeTelemetryCollector:
    """Collects real-time telemetry, operational metrics, and SLA heartbeats for regulated workloads."""

    def __init__(self, framework_id: str):
        self.framework_id = framework_id
        self.events: List[Dict[str, Any]] = []

    def record_event(self, event_name: str, status: str, latency_ms: float, details: Dict[str, Any]) -> Dict[str, Any]:
        event = {
            "framework_id": self.framework_id,
            "event_name": event_name,
            "status": status,
            "latency_ms": latency_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details
        }
        self.events.append(event)
        return event

    def get_summary(self) -> Dict[str, Any]:
        total = len(self.events)
        successes = sum(1 for e in self.events if e["status"] == "SUCCESS")
        avg_latency = sum(e["latency_ms"] for e in self.events) / max(1, total)
        return {
            "framework_id": self.framework_id,
            "total_events": total,
            "success_rate_pct": round((successes / max(1, total)) * 100.0, 2),
            "average_latency_ms": round(avg_latency, 2),
            "last_event_time": self.events[-1]["timestamp"] if self.events else None
        }
