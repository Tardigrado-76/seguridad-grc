"""Quantigrade GCR - Privacy Rights Automation (SAR / ARCO) & Third-Party Risk Management (TPRM).

Automates Data Subject Access Requests (SAR) under GDPR Art. 12-22 with strict 30-day legal countdowns,
and third-party ICT supply chain risk assessment under DORA Art. 28 and NIS2 Art. 21.2.d.
Runs 100% natively in Python without Docker.
"""

import time
import hashlib
from typing import Dict, Any, List, Optional

class PrivacySARManager:
    """Manages data subject requests (SAR / ARCO) with statutory deadline enforcement under GDPR Art. 12.3."""

    VALID_RIGHTS = {
        "Access",
        "Erasure",
        "Rectification",
        "Portability",
        "Restriction",
        "Objection"
    }

    def __init__(self):
        self.requests: Dict[str, Dict[str, Any]] = {}

    def create_sar_request(
        self,
        request_id: str,
        subject_email: str,
        request_type: str,
        intake_timestamp: Optional[float] = None
    ) -> Dict[str, Any]:
        """Creates a data subject request with strict 30-day statutory countdown."""
        norm_type = request_type.strip().capitalize()
        if norm_type not in self.VALID_RIGHTS:
            raise ValueError(f"Invalid request type '{request_type}'. Must be one of {self.VALID_RIGHTS}.")

        now = intake_timestamp if intake_timestamp is not None else time.time()
        statutory_deadline = now + (30 * 86400)  # Exactly 30 days under Art. 12.3 RGPD

        req = {
            "request_id": request_id,
            "subject_email": subject_email,
            "request_type": norm_type,
            "status": "PROCESSING",
            "intake_timestamp": now,
            "deadline_timestamp": statutory_deadline,
            "extended_deadline": False,
            "resolution_notes": None,
            "delivery_proof_hash": None,
            "closed_at": None
        }
        self.requests[request_id] = req
        return req

    def extend_request(self, request_id: str, legal_justification: str) -> Dict[str, Any]:
        """Extends statutory deadline by up to 2 additional months (60 days) for complex requests under GDPR Art. 12.3."""
        if request_id not in self.requests:
            raise KeyError(f"SAR request '{request_id}' not found.")
        req = self.requests[request_id]
        if req["extended_deadline"]:
            raise ValueError("SAR request has already been granted the maximum legal extension (Art. 12.3).")
        
        req["extended_deadline"] = True
        req["deadline_timestamp"] += (60 * 86400)
        req["extension_justification"] = legal_justification
        return req

    def close_sar_request(
        self,
        request_id: str,
        resolution_notes: str,
        delivery_payload: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fulfills and closes a SAR request with an immutable cryptographic proof hash."""
        if request_id not in self.requests:
            raise KeyError(f"SAR request '{request_id}' not found.")
        req = self.requests[request_id]
        now = time.time()
        
        proof_data = f"{request_id}:{req['subject_email']}:{resolution_notes}:{delivery_payload or ''}:{now}".encode("utf-8")
        proof_hash = hashlib.sha256(proof_data).hexdigest()

        req["status"] = "COMPLETED"
        req["resolution_notes"] = resolution_notes
        req["delivery_proof_hash"] = proof_hash
        req["closed_at"] = now
        return req

    def extract_subject_pii(self, request_id: str, target_db: str = "mock", dry_run: bool = True) -> Dict[str, Any]:
        """Extracts all PII for the subject of a SAR request using the SARDataExtractor engine."""
        if request_id not in self.requests:
            raise KeyError(f"SAR request '{request_id}' not found.")
        req = self.requests[request_id]
        from core_mesh.operational.sar_data_extractor import SARDataExtractor
        extractor = SARDataExtractor(subject_identifier=req["subject_email"], target_db=target_db, dry_run=dry_run)
        records = extractor.process_sar_extraction()
        return {
            "request_id": request_id,
            "subject_email": req["subject_email"],
            "records_count": len(records),
            "records": records
        }

    def get_request_status(self, request_id: str, current_timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Calculates days remaining and statutory urgency status."""
        if request_id not in self.requests:
            raise KeyError(f"SAR request '{request_id}' not found.")
        req = self.requests[request_id]
        now = current_timestamp if current_timestamp is not None else time.time()

        if req["status"] == "COMPLETED":
            return {
                "request_id": request_id,
                "status": "COMPLETED",
                "urgency_level": "RESOLVED",
                "days_remaining": 0.0,
                "delivery_proof_hash": req["delivery_proof_hash"]
            }

        diff_sec = req["deadline_timestamp"] - now
        days_rem = round(diff_sec / 86400.0, 1)

        if days_rem < 0:
            urgency = "BREACH_OVERDUE"
        elif days_rem <= 5.0:
            urgency = "CRITICAL"
        elif days_rem <= 15.0:
            urgency = "ATTENTION"
        else:
            urgency = "NORMAL"

        return {
            "request_id": request_id,
            "subject_email": req["subject_email"],
            "request_type": req["request_type"],
            "status": req["status"],
            "urgency_level": urgency,
            "days_remaining": days_rem,
            "is_extended": req["extended_deadline"]
        }

    def get_summary(self, current_timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Produces corporate GDPR rights compliance overview."""
        total = len(self.requests)
        completed = 0
        overdue = 0
        critical = 0

        for rid in self.requests:
            st = self.get_request_status(rid, current_timestamp)
            if st["status"] == "COMPLETED":
                completed += 1
            elif st["urgency_level"] == "BREACH_OVERDUE":
                overdue += 1
            elif st["urgency_level"] == "CRITICAL":
                critical += 1

        active = total - completed
        return {
            "total_requests": total,
            "active_requests": active,
            "completed_requests": completed,
            "overdue_requests": overdue,
            "critical_approaching_sla": critical,
            "statutory_compliance_rate": round(((total - overdue) / max(1, total)) * 100.0, 1)
        }


class VendorTPRMManager:
    """Third-Party Risk Management engine for DORA Art. 28, NIS2 Art. 21.2.d, and Schrems II compliance."""

    VALID_TIERS = {"TIER_1", "TIER_2", "TIER_3"}

    def __init__(self):
        self.vendors: Dict[str, Dict[str, Any]] = {}

    def register_vendor(
        self,
        vendor_id: str,
        vendor_name: str,
        service_description: str,
        criticality_tier: str,
        data_hosted_in_eea: bool,
        questionnaire_score: float,
        has_exit_strategy: bool = True,
        transfer_mechanism: Optional[str] = None
    ) -> Dict[str, Any]:
        """Registers and evaluates third-party vendor risk."""
        norm_tier = criticality_tier.strip().upper()
        if norm_tier not in self.VALID_TIERS:
            raise ValueError(f"Invalid criticality tier '{criticality_tier}'. Must be one of {self.VALID_TIERS}.")

        score = max(0.0, min(100.0, float(questionnaire_score)))
        
        # Schrems II assessment
        if data_hosted_in_eea:
            schrems_status = "ADEQUATE_EEA"
            schrems_risk = "LOW"
        else:
            if transfer_mechanism and any(m in transfer_mechanism.upper() for m in ["SCC", "DPF", "BCR"]):
                schrems_status = f"SAFEGUARDED_{transfer_mechanism.upper()}"
                schrems_risk = "MEDIUM"
            else:
                schrems_status = "SCHREMS_II_HIGH_RISK"
                schrems_risk = "HIGH"

        # DORA Art. 28 compliance
        dora_findings: List[str] = []
        if norm_tier == "TIER_1":
            if not has_exit_strategy:
                dora_findings.append("DORA Art. 28 Violation: Tier 1 Critical Vendor lacks documented and tested exit strategy.")
            if score < 75.0:
                dora_findings.append("DORA Vendor Security Deficiency: Security assessment score is below Tier 1 minimum threshold (75%).")

        # Composite TPRM Score (0 - 100)
        composite = score * 0.6
        if data_hosted_in_eea:
            composite += 20.0
        elif schrems_risk == "MEDIUM":
            composite += 10.0
        
        if has_exit_strategy:
            composite += 20.0
        elif norm_tier == "TIER_3":
            composite += 10.0

        composite = round(min(100.0, composite), 1)
        if composite >= 80.0:
            overall_risk = "LOW_RISK"
        elif composite >= 55.0:
            overall_risk = "MODERATE_RISK"
        else:
            overall_risk = "HIGH_RISK"

        record = {
            "vendor_id": vendor_id,
            "vendor_name": vendor_name,
            "service_description": service_description,
            "criticality_tier": norm_tier,
            "data_hosted_in_eea": data_hosted_in_eea,
            "transfer_mechanism": transfer_mechanism,
            "schrems_status": schrems_status,
            "schrems_risk": schrems_risk,
            "has_exit_strategy": has_exit_strategy,
            "questionnaire_score": score,
            "composite_tprm_score": composite,
            "overall_risk": overall_risk,
            "dora_findings": dora_findings,
            "registered_at": time.time()
        }
        self.vendors[vendor_id] = record
        return record

    def get_critical_vendors(self) -> List[Dict[str, Any]]:
        """Returns all Tier 1 critical ICT providers with their DORA posture."""
        return [v for v in self.vendors.values() if v["criticality_tier"] == "TIER_1"]

    def get_tprm_summary(self) -> Dict[str, Any]:
        """Summarizes supply chain security posture."""
        total = len(self.vendors)
        tier_counts = {"TIER_1": 0, "TIER_2": 0, "TIER_3": 0}
        schrems_high_risk = 0
        dora_violations_count = 0
        score_sum = 0.0

        for v in self.vendors.values():
            tier_counts[v["criticality_tier"]] += 1
            if v["schrems_risk"] == "HIGH":
                schrems_high_risk += 1
            if v["dora_findings"]:
                dora_violations_count += 1
            score_sum += v["composite_tprm_score"]

        avg_score = round(score_sum / max(1, total), 1)
        return {
            "total_vendors": total,
            "critical_tier1_count": tier_counts["TIER_1"],
            "significant_tier2_count": tier_counts["TIER_2"],
            "standard_tier3_count": tier_counts["TIER_3"],
            "schrems_high_risk_vendors": schrems_high_risk,
            "dora_violations_count": dora_violations_count,
            "average_tprm_score": avg_score
        }
