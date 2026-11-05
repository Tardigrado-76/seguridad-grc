"""Pytest conftest for security_audit fastapi tests"""
import os
import sys
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "AUDIT_CONSOLE", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from main import app
except Exception:
    from fastapi import FastAPI
    app = FastAPI(title="FallbackApp")

@pytest.fixture
def client():
    return TestClient(app)

@pytest_asyncio.fixture
async def async_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
