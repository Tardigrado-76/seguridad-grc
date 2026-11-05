"""Pytest conftest for security_audit fastapi tests."""
import os
import sys
from pathlib import Path
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

# Point to real audit-console backend in RegTech & AI-SecOps Appliance
repo_root = Path(__file__).resolve().parents[4]
backend_dir = repo_root / "1_PORTAL_CLIENTE" / "3_audit-console" / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app

@pytest.fixture
def client():
    return TestClient(app)

@pytest_asyncio.fixture
async def async_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
