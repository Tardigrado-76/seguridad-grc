#!/usr/bin/env python3
"""
ctem_exposure_scorer.py — CTEM Phase 3: Continuous Threat Exposure Index & Prioritization Scorer.
Computes a normalized exposure score (0.0 to 100.0) per compliance framework and overall risk tier.
Aligns with:
 - Gartner CTEM Framework (Discovery, Scoping, Prioritization, Validation, Mobilization)
 - CVSS v3.1 / v4.0 Vulnerability Scoring Principles
 - ENS RD 311/2022: Gestión Continua de la Seguridad
"""
from __future__ import annotations

import datetime
from typing import Any


class CTEMExposureScorer:
    """Aggregates and normalizes multi-source CTEM findings into unified exposure ratings."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 35.0,
        "HIGH": 15.0,
        "MEDIUM": 6.0,
        "LOW": 2.0,
        "INFO": 0.0,
    }

    FRAMEWORK_MAPPINGS = {
        "ENS": ["op.acc", "op.vul", "mp.sw", "mp.com", "ENS"],
        "NIS2": ["NIS2", "ciberhigiene", "supply_chain"],
        "DORA": ["DORA", "ICT", "resilience", "exit_strategy"],
        "EU_AI_ACT": ["Art. 5", "Art. 6", "Art. 10", "Art. 12", "Art. 14", "EU AI Act"],
        "OWASP": ["A01", "OWASP", "BOLA", "IDOR", "LLM01", "LLM03"],
        "RGPD": ["RGPD", "GDPR", "retention", "breach"],
    }

    def compute_framework_scores(self, findings: list[dict[str, Any]]) -> dict[str, float]:
        """Calculates exposure score per framework. 0.0 = Minimum Exposure (Secure), 100.0 = Critical Exposure."""
        raw_scores: dict[str, float] = {fw: 0.0 for fw in self.FRAMEWORK_MAPPINGS}

        for f in findings:
            sev = f.get("severity", "LOW").upper()
            weight = self.SEVERITY_WEIGHTS.get(sev, 2.0)
            text_repr = f"{f.get('type', '')} {f.get('compliance_ref', '')} {f.get('description', '')} {f.get('article', '')} {f.get('control', '')}"

            matched = False
            for fw, patterns in self.FRAMEWORK_MAPPINGS.items():
                if any(p.lower() in text_repr.lower() for p in patterns):
                    raw_scores[fw] += weight
                    matched = True

            if not matched:
                raw_scores["ENS"] += weight * 0.5
                raw_scores["NIS2"] += weight * 0.5

        # Normalize each score into [0.0, 100.0]
        normalized = {fw: min(100.0, round(score, 1)) for fw, score in raw_scores.items()}
        return normalized

    def calculate_overall_rating(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        fw_scores = self.compute_framework_scores(findings)
        max_score = max(fw_scores.values()) if fw_scores else 0.0
        avg_score = sum(fw_scores.values()) / len(fw_scores) if fw_scores else 0.0

        # Exposure index weighted towards highest exposed framework
        overall_index = round((0.6 * max_score) + (0.4 * avg_score), 1)

        if overall_index >= 70.0:
            tier = "CRITICAL_EXPOSURE"
            urgency = "IMMEDIATE_ACTION_REQUIRED"
        elif overall_index >= 40.0:
            tier = "ELEVATED_EXPOSURE"
            urgency = "PRIORITIZED_REMEDIATION"
        elif overall_index >= 15.0:
            tier = "MODERATE_EXPOSURE"
            urgency = "SCHEDULED_MITIGATION"
        else:
            tier = "LOW_EXPOSURE"
            urgency = "CONTINUOUS_MONITORING"

        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_findings_evaluated": len(findings),
            "exposure_index": overall_index,
            "risk_tier": tier,
            "action_urgency": urgency,
            "framework_exposures": fw_scores
        }

