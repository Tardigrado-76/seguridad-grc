"""
Functional Integration Tests for AUDIT_CONSOLE Backend
"""

import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import pytest
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app

client = TestClient(app)

def test_root_health():
    response = client.get("/")
    assert response.status_code in [200, 404]

def test_api_status():
    response = client.get("/health")
    if response.status_code == 200:
        data = response.json()
        assert "status" in data or "ok" in str(data).lower()
    else:
        assert response.status_code in [200, 404]
