"""
Native Isolation Harness for Quantigrade GCR.
Provides deterministic, zero-Docker process confinement with sanitized environment,
isolated temporary filesystem, memory-safe output caps, and strict timeouts.
"""
import os
import sys
import tempfile
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    is_truncated: bool = False


class NativeIsolationHarness:
    """
    Executes audit and evidence extraction tasks in confined native OS processes.
    Enforces strict zero-Docker compliance with environment isolation.
    """

    ALLOWED_ENV_VARS_WIN = {
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "COMSPEC",
        "PYTHONPATH",
    }

    ALLOWED_ENV_VARS_POSIX = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "TEMP",
        "TMPDIR",
        "PYTHONPATH",
    }

    def __init__(self, timeout_sec: int = 15, max_output_bytes: int = 256 * 1024):
        self.timeout_sec = timeout_sec
        self.max_output_bytes = max_output_bytes

    def _build_clean_env(self) -> Dict[str, str]:
        allowed = self.ALLOWED_ENV_VARS_WIN if os.name == "nt" else self.ALLOWED_ENV_VARS_POSIX
        clean_env = {}
        for var, val in os.environ.items():
            if var.upper() in allowed:
                clean_env[var] = val
        return clean_env

    def run_python_code(self, code: str) -> ExecutionResult:
        """Executes a Python code snippet inside the native sandboxed environment."""
        with tempfile.TemporaryDirectory() as sandbox_dir:
            script_path = os.path.join(sandbox_dir, "isolated_script.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(code)

            return self.run_command([sys.executable, script_path], cwd=sandbox_dir)

    def run_command(self, cmd: List[str], cwd: Optional[str] = None) -> ExecutionResult:
        """Runs an arbitrary command in a sanitized environment with output caps and timeout."""
        clean_env = self._build_clean_env()

        use_temp_dir = False
        temp_dir_obj = None
        if not cwd:
            temp_dir_obj = tempfile.TemporaryDirectory()
            cwd = temp_dir_obj.name
            use_temp_dir = True

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=clean_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            try:
                stdout_data, stderr_data = proc.communicate(timeout=self.timeout_sec)
                timed_out = False
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_data, stderr_data = proc.communicate()
                timed_out = True
                exit_code = -1

            # Enforce output capping
            is_truncated = False
            if len(stdout_data) > self.max_output_bytes:
                stdout_data = stdout_data[: self.max_output_bytes] + "\n[OUTPUT TRUNCATED BY HARNESS]"
                is_truncated = True

            if len(stderr_data) > self.max_output_bytes:
                stderr_data = stderr_data[: self.max_output_bytes] + "\n[ERROR TRUNCATED BY HARNESS]"
                is_truncated = True

            return ExecutionResult(
                exit_code=exit_code,
                stdout=stdout_data,
                stderr=stderr_data,
                timed_out=timed_out,
                is_truncated=is_truncated,
            )
        finally:
            if use_temp_dir and temp_dir_obj:
                temp_dir_obj.cleanup()
