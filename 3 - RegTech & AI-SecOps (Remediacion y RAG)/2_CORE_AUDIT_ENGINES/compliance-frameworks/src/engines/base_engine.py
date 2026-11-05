"""
Base Compliance Engine — Abstract class for all normative engines.
All engines (DORA, NIS2, ENS, etc.) inherit from this.
"""
import hashlib
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from shared.logger import get_logger


class BaseComplianceEngine(ABC):
    """
    Abstract base for all compliance engines.
    Enforces: structured logging, evidence sealing, standardised results.
    """

    ENGINE_NAME: str = "base"
    ENGINE_VERSION: str = "1.0.0"

    def __init__(self, target_path: str, mode: str = "AUDIT_ONLY", agent_id: str = "system"):
        self.target_path = Path(target_path)
        self.mode = mode  # AUDIT_ONLY | REMEDIATE
        self.log = get_logger(self.ENGINE_NAME, agent_id=agent_id)
        self.results: list[dict] = []
        self.evidences: list[dict] = []
        self._started_at = datetime.now(timezone.utc)

    @abstractmethod
    def run(self) -> dict:
        """Execute the compliance audit. Returns a structured result dict."""
        ...

    def _seal_evidence(self, name: str, content: str, evidence_dir: str = "evidences") -> dict:
        """Save and cryptographically seal an evidence artefact (SHA-256)."""
        ev_dir = Path(evidence_dir)
        ev_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"EVIDENCE_{ts}_{self.ENGINE_NAME.upper()}_{name}.log"
        filepath = ev_dir / filename

        filepath.write_text(content, encoding="utf-8")
        file_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()

        meta = {
            "engine": self.ENGINE_NAME,
            "evidence_name": name,
            "filename": filename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sha256_hash": file_hash,
            "status": "SEALED_AND_VERIFIED",
        }
        (ev_dir / f"EVIDENCE_{ts}_{self.ENGINE_NAME.upper()}_{name}.meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        self.evidences.append(meta)
        self.log.info("Evidence sealed", filename=filename, sha256=file_hash)
        return meta

    def _build_report(self) -> dict:
        """Assemble a standardised audit report dictionary."""
        elapsed = (datetime.now(timezone.utc) - self._started_at).total_seconds()
        total = len(self.results)
        passed = sum(1 for r in self.results if r.get("success"))
        score = round((passed / total * 100), 2) if total > 0 else 0.0
        return {
            "engine": self.ENGINE_NAME,
            "version": self.ENGINE_VERSION,
            "target_path": str(self.target_path),
            "mode": self.mode,
            "timestamp": self._started_at.isoformat(),
            "elapsed_seconds": elapsed,
            "score": score,
            "passed": passed,
            "total": total,
            "results": self.results,
            "evidences": self.evidences,
        }