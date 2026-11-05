"""
Shared logger module — Fail-Closed pattern.
If the logger cannot initialize, the system should NOT start.
Compliant with: NIS2 Art.20, ENS logging requirements.
"""
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


class StructuredLogger:
    """
    JSON Structured Logger with Fail-Closed enforcement.
    Adds Agent-ID and Trace-ID for multi-agent traceability.
    """

    def __init__(self, name, log_dir="logs", agent_id="system", trace_id=None):
        self.name = name
        self.agent_id = agent_id
        self.trace_id = trace_id or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        self.log_dir = Path(log_dir)

        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            # FAIL-CLOSED: If we cannot create the log directory, abort.
            print(f"[CRITICAL] Logger init failed — cannot create log dir: {e}", file=sys.stderr)
            sys.exit(1)

        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)

        log_file = self.log_dir / f"{name}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(file_handler)
        except OSError as e:
            print(f"[CRITICAL] Logger init failed — cannot open log file: {e}", file=sys.stderr)
            sys.exit(1)

        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(console_handler)

    def _emit(self, level, message, extra=None):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "logger": self.name,
            "agent_id": self.agent_id,
            "trace_id": self.trace_id,
            "message": message,
        }
        if extra:
            record["extra"] = extra
        self._logger.log(getattr(logging, level), json.dumps(record, ensure_ascii=False))

    def info(self, message, **extra): self._emit("INFO", message, extra or None)
    def warning(self, message, **extra): self._emit("WARNING", message, extra or None)
    def error(self, message, **extra): self._emit("ERROR", message, extra or None)
    def critical(self, message, **extra): self._emit("CRITICAL", message, extra or None)
    def debug(self, message, **extra): self._emit("DEBUG", message, extra or None)


def get_logger(name, agent_id="system", log_dir="logs"):
    """Factory function. Use this in all modules."""
    return StructuredLogger(name=name, agent_id=agent_id, log_dir=log_dir)