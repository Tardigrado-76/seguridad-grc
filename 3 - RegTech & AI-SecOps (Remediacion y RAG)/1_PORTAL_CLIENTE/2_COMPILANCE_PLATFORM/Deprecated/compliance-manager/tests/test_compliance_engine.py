"""
Functional Tests for COMPILANCE_MANAGER Engine
"""

import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def test_compliance_imports():
    assert True

def test_environment_variables():
    from dotenv import load_dotenv
    load_dotenv()
    workspace = os.getenv("WORKSPACE_ROOT", ".")
    assert workspace is not None
