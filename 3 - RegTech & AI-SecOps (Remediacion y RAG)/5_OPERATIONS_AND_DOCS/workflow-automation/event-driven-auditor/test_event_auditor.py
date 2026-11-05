"""test_event_auditor.py — Unit & Integration Tests for Event-Driven AI Auditor.
============================================================================
Pruebas automatizadas de ingesta reactiva, detección de anomalías y alertas regulatorias.
"""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).parent.resolve()
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import time

from consumer import EventStreamConsumer
from log_auditor_agent import SeverityLevel, StreamLogAuditorAgent
from producer_simulator import TelemetryEventProducer


def test_log_auditor_normal_traffic() -> None:
    agent = StreamLogAuditorAgent()
    normal_event = {
        "event_id": "normal-1",
        "service": "api-gateway",
        "action": "http_get_200",
        "user_id": "usr_100",
    }
    incident = agent.evaluate_event(normal_event)
    assert incident is None


def test_log_auditor_critical_dora_incident() -> None:
    agent = StreamLogAuditorAgent()
    dora_event = {
        "event_id": "dora-fail-1",
        "service": "core-banking",
        "action": "service_down database_unreachable timeout",
        "user_id": "system",
    }
    incident = agent.evaluate_event(dora_event)
    assert incident is not None
    assert incident["highest_severity"] == SeverityLevel.CRITICAL
    assert any(r["framework"] == "DORA Art. 18" for r in incident["matched_rules"])
    assert "cryptographic_proof_sha256" in incident


def test_log_auditor_prompt_injection_incident() -> None:
    agent = StreamLogAuditorAgent()
    ai_act_event = {
        "event_id": "ai-hack-1",
        "service": "llm-gateway",
        "action": "prompt_injection override_guardrail",
        "user_id": "attacker_ip",
    }
    incident = agent.evaluate_event(ai_act_event)
    assert incident is not None
    assert incident["highest_severity"] == SeverityLevel.HIGH
    assert any("EU AI Act" in r["framework"] for r in incident["matched_rules"])


def test_event_stream_consumer_pipeline() -> None:
    consumer = EventStreamConsumer()
    consumer.start_worker()

    events = TelemetryEventProducer.generate_batch(size=20, incident_ratio=0.5)
    for ev in events:
        consumer.publish_event(ev)

    time.sleep(0.3)
    consumer.stop_worker()

    stats = consumer.get_stats()
    assert stats["total_processed_events"] == 20
    assert stats["total_alerts_dispatched"] > 0
    assert stats["dlq_size"] == 0
