"""
N8n Remediation Dispatcher for Quantigrade GCR.
Zero-Docker automation dispatcher connecting to local or remote n8n workflows
using HMAC-SHA256 authenticated webhooks and cryptographic receipt logging.
"""
import hmac
import hashlib
import json
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class RemediationDispatchResult:
    task_id: str
    success: bool
    status_code: int
    receipt_hash: str
    correlation_id: str
    message: str = ""
    response_data: Dict[str, Any] = field(default_factory=dict)


class N8nRemediationDispatcher:
    """
    Dispatches automated compliance remediation actions to n8n workflows
    (e.g., Jira ticket creation, AWS IAM key rotation, GitHub branch protection, Slack alerts)
    without Docker dependencies.
    """

    def __init__(self, webhook_url: str = "http://localhost:5678/webhook/grc-remediation", secret_key: str = "quantigrade_n8n_hmac_secret"):
        self.webhook_url = webhook_url
        self.secret_key = secret_key.encode("utf-8")

    def compute_signature(self, data: Dict[str, Any]) -> str:
        """Computes a deterministic HMAC-SHA256 signature for a payload."""
        canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self.secret_key, canonical_json, hashlib.sha256).hexdigest()

    def prepare_signed_payload(self, task_id: str, action_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Packages and signs a remediation action."""
        pkg = {
            "task_id": task_id,
            "action_name": action_name,
            "timestamp": int(time.time()),
            "payload": payload,
        }
        pkg["hmac_signature"] = self.compute_signature(pkg)
        return pkg

    def verify_callback_signature(self, data: Dict[str, Any], signature: str) -> bool:
        """Verifies an incoming callback signature from an n8n webhook."""
        expected = self.compute_signature(data)
        return hmac.compare_digest(expected, signature)

    def dispatch_task(
        self,
        task_id: str,
        action_name: str,
        payload: Dict[str, Any],
        simulate: bool = False,
    ) -> RemediationDispatchResult:
        """
        Dispatches a task to n8n. If simulate=True, generates receipts without network calls.
        """
        signed_pkg = self.prepare_signed_payload(task_id, action_name, payload)
        correlation_id = f"corr_{hashlib.sha256(f'{task_id}:{time.time()}'.encode('utf-8')).hexdigest()[:12]}"
        receipt_hash = hashlib.sha256(json.dumps(signed_pkg, sort_keys=True).encode("utf-8")).hexdigest()

        if simulate:
            return RemediationDispatchResult(
                task_id=task_id,
                success=True,
                status_code=200,
                receipt_hash=receipt_hash,
                correlation_id=correlation_id,
                message="[SIMULATED_DISPATCH] Task successfully dispatched to n8n simulator.",
                response_data={"simulated": True, "action": action_name},
            )

        # Real HTTP dispatch via Python stdlib
        try:
            req_data = json.dumps(signed_pkg).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "X-GCR-HMAC-SHA256": signed_pkg["hmac_signature"],
                    "X-GCR-Correlation-ID": correlation_id,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status_code = resp.getcode()
                resp_body = json.loads(resp.read().decode("utf-8"))
                return RemediationDispatchResult(
                    task_id=task_id,
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    receipt_hash=receipt_hash,
                    correlation_id=correlation_id,
                    message="Dispatched to n8n successfully.",
                    response_data=resp_body if isinstance(resp_body, dict) else {"raw": resp_body},
                )
        except Exception as exc:
            return RemediationDispatchResult(
                task_id=task_id,
                success=False,
                status_code=500,
                receipt_hash=receipt_hash,
                correlation_id=correlation_id,
                message=f"n8n dispatch failed: {str(exc)}",
            )
