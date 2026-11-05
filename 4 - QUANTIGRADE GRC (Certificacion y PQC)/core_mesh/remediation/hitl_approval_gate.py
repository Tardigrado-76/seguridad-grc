from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional

class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

class RemediationApprovalRequest:
    def __init__(self, action_id: str, framework: str, description: str, impact_level: str):
        self.request_id = f"HITL-{uuid.uuid4().hex[:8].upper()}"
        self.action_id = action_id
        self.framework = framework
        self.description = description
        self.impact_level = impact_level
        self.status = ApprovalStatus.PENDING
        self.decided_by: Optional[str] = None
        self.decided_at: Optional[str] = None
        self.comments: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "action_id": self.action_id,
            "framework": self.framework,
            "description": self.description,
            "impact_level": self.impact_level,
            "status": self.status.value,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "comments": self.comments
        }

class HITLApprovalGate:
    """Human-in-the-Loop decision gate for high-risk technical remediations."""

    def __init__(self):
        self.requests: Dict[str, RemediationApprovalRequest] = {}

    def submit_request(self, action_id: str, framework: str, description: str, impact_level: str) -> RemediationApprovalRequest:
        req = RemediationApprovalRequest(action_id, framework, description, impact_level)
        self.requests[req.request_id] = req
        return req

    def decide(self, request_id: str, approved: bool, officer_id: str, comments: str = "") -> Dict[str, Any]:
        if request_id not in self.requests:
            raise KeyError(f"Request {request_id} not found.")
        req = self.requests[request_id]
        req.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        req.decided_by = officer_id
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.comments = comments
        return req.to_dict()
