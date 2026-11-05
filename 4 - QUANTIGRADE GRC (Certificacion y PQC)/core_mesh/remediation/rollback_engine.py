from __future__ import annotations
import logging
from typing import List, Dict, Any, Callable

logger = logging.getLogger("RollbackEngine")

class RollbackEngine:
    """Coordinates saga rollbacks and compensating transactions when a remediation fails."""

    def __init__(self):
        self.compensating_actions: List[Dict[str, Any]] = []

    def register_compensation(self, name: str, rollback_fn: Callable, *args, **kwargs):
        self.compensating_actions.append({"name": name, "fn": rollback_fn, "args": args, "kwargs": kwargs})

    def execute_rollback(self) -> List[Dict[str, Any]]:
        results = []
        logger.warning(f"Executing rollback across {len(self.compensating_actions)} compensating steps...")
        for step in reversed(self.compensating_actions):
            try:
                res = step["fn"](*step["args"], **step["kwargs"])
                results.append({"step": step["name"], "status": "COMPENSATED", "result": res})
            except Exception as e:
                logger.error(f"Rollback failed on step {step['name']}: {e}")
                results.append({"step": step["name"], "status": "FAILED", "error": str(e)})
        self.compensating_actions.clear()
        return results
