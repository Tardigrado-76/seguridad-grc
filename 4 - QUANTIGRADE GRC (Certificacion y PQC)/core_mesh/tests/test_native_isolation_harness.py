"""
Tests for NativeIsolationHarness: Cero-Docker local sandboxing.
"""
import os
import sys
import pytest
from core_mesh.operational.native_isolation_harness import (
    NativeIsolationHarness,
    ExecutionResult,
)


def test_native_isolation_harness_cleans_env():
    # Set a sensitive dummy key in current process
    os.environ["SENSITIVE_SECRET_TOKEN"] = "SUPER_SECRET_12345"
    harness = NativeIsolationHarness()

    # Query the child env for that secret
    code = 'import os; print("FOUND:" + os.environ.get("SENSITIVE_SECRET_TOKEN", "NONE"))'
    res = harness.run_python_code(code)

    assert res.exit_code == 0
    assert "FOUND:NONE" in res.stdout
    assert "SUPER_SECRET_12345" not in res.stdout


def test_native_isolation_harness_timeout_enforcement():
    harness = NativeIsolationHarness(timeout_sec=1)
    code = "import time; time.sleep(5)"
    res = harness.run_python_code(code)

    assert res.timed_out is True
    assert res.exit_code != 0


def test_native_isolation_harness_output_cap():
    # Limit to 500 bytes
    harness = NativeIsolationHarness(max_output_bytes=500)
    code = 'print("A" * 5000)'
    res = harness.run_python_code(code)

    assert res.exit_code == 0
    assert len(res.stdout) <= 600
    assert res.is_truncated is True


def test_native_isolation_harness_clean_working_dir():
    harness = NativeIsolationHarness()
    code = 'import os; os.system("echo test_file > created_in_sandbox.txt")'
    res = harness.run_python_code(code)
    assert res.exit_code == 0
    # The file must NOT exist in current directory
    assert not os.path.exists("created_in_sandbox.txt")
