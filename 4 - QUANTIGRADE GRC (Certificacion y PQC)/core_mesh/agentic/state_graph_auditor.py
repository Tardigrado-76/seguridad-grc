"""
Deterministic State Graph Auditor for Quantigrade GCR.
Lightweight, pure-Python Directed Acyclic Graph (DAG) state machine with
SQLite WAL checkpointing for fail-safe, repeatable compliance investigations.
"""
import sqlite3
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Callable, Optional


@dataclass
class NodeResult:
    next_node: Optional[str]
    updates: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphState:
    current_node: str
    context: Dict[str, Any] = field(default_factory=dict)
    execution_path: List[str] = field(default_factory=list)
    step_count: int = 0


class StateGraphAuditor:
    """
    Executes audit investigation workflows as state graphs with failure recovery,
    conditional branching, and durable SQLite WAL persistence.
    """

    def __init__(self, checkpoint_db_path: str = ":memory:"):
        self.db_path = checkpoint_db_path
        self._nodes: Dict[str, Callable[[GraphState], NodeResult]] = {}
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    step_idx INTEGER,
                    node_name TEXT,
                    context_json TEXT,
                    timestamp REAL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def add_node(self, name: str, fn: Callable[[GraphState], NodeResult]):
        """Registers an audit node function into the state machine."""
        self._nodes[name] = fn

    def _save_checkpoint(self, step_idx: int, node_name: str, context: Dict[str, Any]):
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO graph_checkpoints (step_idx, node_name, context_json, timestamp) VALUES (?, ?, ?, ?)",
                (step_idx, node_name, json.dumps(context), time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    def execute(
        self,
        initial_node: str,
        initial_context: Optional[Dict[str, Any]] = None,
        max_steps: int = 50,
    ) -> GraphState:
        """
        Executes the graph iteratively until a terminal node is reached or next_node is None.
        """
        state = GraphState(
            current_node=initial_node,
            context=dict(initial_context or {}),
            execution_path=[initial_node],
            step_count=0,
        )

        while state.step_count < max_steps:
            node_name = state.current_node

            if node_name not in self._nodes:
                # Terminal or unknown node reached
                break

            node_fn = self._nodes[node_name]
            self._save_checkpoint(state.step_count, node_name, state.context)

            # Execute node
            result = node_fn(state)
            state.step_count += 1

            # Apply state updates
            if result.updates:
                state.context.update(result.updates)

            if not result.next_node:
                break

            state.current_node = result.next_node
            state.execution_path.append(result.next_node)

        return state

    def get_checkpoints(self) -> List[Dict[str, Any]]:
        """Retrieves all persisted checkpoints in chronological order."""
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT step_idx, node_name, context_json, timestamp FROM graph_checkpoints ORDER BY id ASC")
            rows = cur.fetchall()
            return [
                {
                    "step_idx": r[0],
                    "node_name": r[1],
                    "context": json.loads(r[2]),
                    "timestamp": r[3],
                }
                for r in rows
            ]
        finally:
            conn.close()
