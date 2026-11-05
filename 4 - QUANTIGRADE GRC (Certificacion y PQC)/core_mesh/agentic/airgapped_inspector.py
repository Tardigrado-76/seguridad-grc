"""Quantigrade GCR - Air-Gapped Local Inspector & Fail-Closed Gateway.

Provides 100% offline inspection and a fail-closed execution gateway
inspired by atomic-agent (SQLite-backed trace persistence, GBNF strict JSON)
and openbot (fail-closed gateway preventing unverified actions).
100% native Python without Docker.
"""

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

class AirGappedInspector:
    """Offline local-first compliance inspector with tamper-evident SQLite traces and fail-closed gateway."""

    def __init__(self, db_path: Optional[str] = None, tenant_id: str = "default_enterprise"):
        self.tenant_id = tenant_id
        if db_path:
            self.db_path = db_path
        else:
            base_dir = Path("data/tenants") / tenant_id
            base_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(base_dir / "airgapped_traces.db")

        self._init_sqlite()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_sqlite(self) -> None:
        """Initializes tamper-evident SQLite schema for local audit traces."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS airgapped_traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT UNIQUE NOT NULL,
                    tenant_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    target_resource TEXT NOT NULL,
                    status TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
            """)
            conn.commit()

    def _get_last_hash(self) -> str:
        """Retrieves the last record hash to maintain the mathematical blockchain-like chain."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT evidence_hash FROM airgapped_traces ORDER BY id DESC LIMIT 1;")
            row = cursor.fetchone()
            return row[0] if row else "0" * 64

    def record_trace(
        self,
        action_name: str,
        target_resource: str,
        status: str,
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Records an air-gapped inspection or gateway decision into SQLite with hash chaining."""
        prev_hash = self._get_last_hash()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        trace_id = f"TRC-{int(time.time() * 1000)}-{os.urandom(3).hex()}"
        details_str = json.dumps(details, sort_keys=True)

        payload_to_hash = f"{trace_id}:{self.tenant_id}:{timestamp}:{action_name}:{target_resource}:{status}:{prev_hash}:{details_str}"
        evidence_hash = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO airgapped_traces (
                    trace_id, tenant_id, timestamp, action_name, target_resource,
                    status, evidence_hash, prev_hash, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (trace_id, self.tenant_id, timestamp, action_name, target_resource, status, evidence_hash, prev_hash, details_str))
            conn.commit()

        return {
            "trace_id": trace_id,
            "evidence_hash": evidence_hash,
            "prev_hash": prev_hash,
            "status": status
        }

    def inspect_local_resource(self, resource_path: str, expected_signatures: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Conducts strictly air-gapped inspection of a local filesystem target."""
        p = Path(resource_path)
        if not p.exists():
            res = {"inspected": False, "error": "Target resource does not exist"}
            self.record_trace("INSPECT_LOCAL", resource_path, "RESOURCE_NOT_FOUND", res)
            return {"status": "NOT_FOUND", "details": res}

        # Calculate cryptographic hash of file or directory state
        if p.is_file():
            content = p.read_bytes()
            content_hash = hashlib.sha256(content).hexdigest()
            res = {
                "inspected": True,
                "is_dir": False,
                "size_bytes": len(content),
                "sha256": content_hash,
                "signature_match": (expected_signatures.get(p.name) == content_hash) if expected_signatures else True
            }
        else:
            files = [str(f.name) for f in p.iterdir() if f.is_file()]
            res = {
                "inspected": True,
                "is_dir": True,
                "file_count": len(files),
                "files_sample": files[:10]
            }

        self.record_trace("INSPECT_LOCAL", resource_path, "INSPECTION_PASSED", res)
        return {"status": "SUCCESS", "details": res}

    def evaluate_fail_closed_gateway(self, remediation_action: Dict[str, Any]) -> Dict[str, Any]:
        """Fail-Closed Gateway (openbot & CRA Art. 10 pattern).
        
        If ANY validation check fails or returns indeterminate state, the remediation action
        is strictly BLOCKED by default rather than blindly executed.
        """
        required_keys = ["action_id", "target_path", "remediation_code", "hitl_approval_signature"]
        missing = [k for k in required_keys if not remediation_action.get(k)]

        if missing:
            block_info = {"reason": f"Faltan campos obligatorios: {missing}", "action": remediation_action}
            self.record_trace("FAIL_CLOSED_GATEWAY", remediation_action.get("target_path", "UNKNOWN"), "BLOCKED_FAIL_CLOSED", block_info)
            return {
                "decision": "BLOCKED_FAIL_CLOSED",
                "allowed": False,
                "reason": f"Fail-Closed activado: Faltan credenciales/firmas obligatorias ({', '.join(missing)})"
            }

        target = str(remediation_action.get("target_path", ""))
        # Path traversal guard
        if ".." in target or target.startswith("/") or (len(target) > 1 and target[1] == ":"):
            # Ensure normalized safe relative target
            if not target.startswith("E:\\PROYECTOS IA\\GCR") and not target.startswith("e:/PROYECTOS IA/GCR") and not target.startswith("config/"):
                block_info = {"reason": "Path traversal o ruta fuera de sandbox detectada", "target": target}
                self.record_trace("FAIL_CLOSED_GATEWAY", target, "BLOCKED_FAIL_CLOSED", block_info)
                return {
                    "decision": "BLOCKED_FAIL_CLOSED",
                    "allowed": False,
                    "reason": "Fail-Closed activado: Ruta fuera de los límites de sandbox autorizados."
                }

        # Signature verification (Simulated HMAC/ECDSA check)
        sig = str(remediation_action.get("hitl_approval_signature", ""))
        if len(sig) < 32 or "invalid" in sig.lower():
            block_info = {"reason": "Firma HITL criptográfica inválida o débil", "sig": sig}
            self.record_trace("FAIL_CLOSED_GATEWAY", target, "BLOCKED_FAIL_CLOSED", block_info)
            return {
                "decision": "BLOCKED_FAIL_CLOSED",
                "allowed": False,
                "reason": "Fail-Closed activado: Firma de aprobación humana no verificada."
            }

        # Passed all gate verifications
        success_info = {"action_id": remediation_action.get("action_id"), "target": target}
        self.record_trace("FAIL_CLOSED_GATEWAY", target, "APPROVED_FOR_EXECUTION", success_info)
        return {
            "decision": "APPROVED_FOR_EXECUTION",
            "allowed": True,
            "target": target
        }

    def verify_trace_integrity(self) -> Dict[str, Any]:
        """Mathematically verifies the integrity of the SQLite hash chain."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT trace_id, tenant_id, timestamp, action_name, target_resource,
                       status, evidence_hash, prev_hash, details_json
                FROM airgapped_traces ORDER BY id ASC;
            """)
            rows = cursor.fetchall()

        if not rows:
            return {"verified": True, "total_records": 0, "status": "EMPTY_DB"}

        expected_prev = "0" * 64
        for idx, r in enumerate(rows):
            trace_id, t_id, timestamp, action, target, status, stored_hash, prev_hash, details_str = r
            if prev_hash != expected_prev:
                return {
                    "verified": False,
                    "status": "CHAIN_BROKEN_AT_PREV_HASH",
                    "broken_at_trace": trace_id,
                    "row_index": idx
                }

            payload = f"{trace_id}:{t_id}:{timestamp}:{action}:{target}:{status}:{prev_hash}:{details_str}"
            calc_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if stored_hash != calc_hash:
                return {
                    "verified": False,
                    "status": "HASH_MISMATCH",
                    "broken_at_trace": trace_id,
                    "row_index": idx
                }
            expected_prev = stored_hash

        return {
            "verified": True,
            "status": "INTEGRITY_VERIFIED",
            "total_records": len(rows),
            "head_hash": expected_prev
        }
