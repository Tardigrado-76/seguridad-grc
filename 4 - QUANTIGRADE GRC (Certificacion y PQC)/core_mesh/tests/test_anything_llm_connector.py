#!/usr/bin/env python3
"""
test_anything_llm_connector.py - TDD Suite for AnythingLLMConnector.
Verifies health check handling, workspace management, strict query mode, and graceful offline fallback.
"""

from __future__ import annotations

from core_mesh.operational.anything_llm_connector import AnythingLLMConnector


def test_connector_initialization():
    conn = AnythingLLMConnector(base_url="http://localhost:3001/api/v1", api_key="secret-token")
    assert conn.base_url == "http://localhost:3001/api/v1"
    assert conn.headers["Authorization"] == "Bearer secret-token"


def test_health_check_offline_graceful():
    # Points to a local port where server is not listening
    conn = AnythingLLMConnector(base_url="http://127.0.0.1:54321/api/v1", timeout_seconds=0.1)
    is_up = conn.health_check()
    assert is_up is False


def test_get_or_create_workspace_offline_fallback():
    conn = AnythingLLMConnector(base_url="http://127.0.0.1:54321/api/v1", timeout_seconds=0.1)
    ws = conn.get_or_create_workspace("Defense DGAM", "dgam-defense")
    assert ws["name"] == "Defense DGAM"
    assert ws["slug"] == "dgam-defense"
    assert ws.get("offline_mode") is True


def test_query_workspace_strict_query_mode_offline_fallback():
    conn = AnythingLLMConnector(base_url="http://127.0.0.1:54321/api/v1", timeout_seconds=0.1)
    res = conn.query_workspace("dora-banking", "¿Cuáles son los requisitos de reporte TIC?", mode="query")
    assert res["status"] == "OFFLINE_FALLBACK"
    assert res["workspace"] == "dora-banking"
    assert res["mode"] == "query"
    assert len(res["sources"]) > 0
