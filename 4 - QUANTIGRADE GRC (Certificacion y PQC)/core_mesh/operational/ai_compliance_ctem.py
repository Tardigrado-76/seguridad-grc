#!/usr/bin/env python3
"""
ai_compliance_ctem.py — CTEM Validation: EU AI Act (Reglamento UE 2024/1689) & AI Governance Engine.
Aligns with:
 - EU AI Act: Art. 5 (Prácticas Prohibidas), Art. 6/Anexo III (Alto Riesgo), Art. 9-14 (Gobernanza y Supervisión Humana)
 - OWASP LLM Top 10 (2025): LLM01, LLM03, LLM07
 - ISO/IEC 42001: Artificial Intelligence Management System
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.AICompliance")


class AIRiskLevel(str, Enum):
    PROHIBITED = "PROHIBITED"       # Art. 5: manipulación subliminal, scoring social
    HIGH_RISK = "HIGH_RISK"         # Art. 6 / Anexo III: infraestructuras críticas, RRHH, legal
    GPAI_SYSTEMIC = "GPAI_SYSTEMIC" # Art. 51: FLOPs > 10^25, modelos fundación
    LIMITED_RISK = "LIMITED_RISK"   # Art. 50: Chatbots, deepfakes, transparencia
    MINIMAL_RISK = "MINIMAL_RISK"   # Filtros de spam, videojuegos, sin riesgo


@dataclass
class AISystemProfile:
    name: str
    description: str
    domain: str  # e.g., "hr_recruiting", "credit_scoring", "internal_qa", "customer_chatbot"
    has_subliminal_manipulation: bool = False
    has_social_scoring: bool = False
    has_realtime_biometrics: bool = False
    is_critical_infrastructure: bool = False
    has_human_oversight: bool = True
    logs_audit_events: bool = True
    has_bias_testing: bool = True


class AIComplianceCTEMEngine:
    """Evaluates AI systems against EU AI Act requirements and generates compliance verdicts."""

    def classify_risk(self, profile: AISystemProfile) -> AIRiskLevel:
        # 1. Prohibited (Art. 5)
        if profile.has_subliminal_manipulation or profile.has_social_scoring or profile.has_realtime_biometrics:
            return AIRiskLevel.PROHIBITED

        # 2. High Risk (Art. 6 / Annex III)
        high_risk_domains = ["hr_recruiting", "credit_scoring", "justice_law_enforcement", "critical_infrastructure", "medical_devices"]
        if profile.domain in high_risk_domains or profile.is_critical_infrastructure:
            return AIRiskLevel.HIGH_RISK

        # 3. Limited Risk (Art. 50 Transparency)
        if "chatbot" in profile.domain or "generative_assistant" in profile.domain:
            return AIRiskLevel.LIMITED_RISK

        return AIRiskLevel.MINIMAL_RISK

    def audit_system(self, profile: AISystemProfile) -> dict[str, Any]:
        risk_level = self.classify_risk(profile)
        findings = []

        if risk_level == AIRiskLevel.PROHIBITED:
            findings.append({
                "article": "Art. 5",
                "severity": "CRITICAL",
                "title": "Práctica de IA Prohibida Detectada",
                "description": "El sistema implementa capacidades expresamente prohibidas por el Reglamento UE 2024/1689.",
                "remediation": "Cese inmediato de la actividad y desmantelamiento del modelo/servicio."
            })

        if risk_level in [AIRiskLevel.HIGH_RISK, AIRiskLevel.GPAI_SYSTEMIC]:
            if not profile.has_human_oversight:
                findings.append({
                    "article": "Art. 14",
                    "severity": "HIGH",
                    "title": "Falta de Supervisión Humana (Human Oversight)",
                    "description": "Los sistemas de alto riesgo deben permitir intervención humana (kill switch / confirmación).",
                    "remediation": "Implementar un flujo de aprobación HITL para decisiones automáticas."
                })
            if not profile.logs_audit_events:
                findings.append({
                    "article": "Art. 12",
                    "severity": "HIGH",
                    "title": "Falta de Trazabilidad y Logs Criptográficos",
                    "description": "Obligación de registrar eventos de inferencia y accesos durante todo el ciclo de vida.",
                    "remediation": "Integrar middleware de logging criptográfico inmutable."
                })
            if not profile.has_bias_testing:
                findings.append({
                    "article": "Art. 10",
                    "severity": "MEDIUM",
                    "title": "Gobernanza y Calidad de Datos / Sesgo No Evaluado",
                    "description": "Se exige mitigación de sesgos estadísticos en datasets de entrenamiento y test.",
                    "remediation": "Ejecutar auditoría de disparidad y paridad demográfica en las predicciones."
                })

        crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")

        score = 100.0
        if risk_level == AIRiskLevel.PROHIBITED:
            score = 0.0
        else:
            score = max(0.0, 100.0 - (crit_count * 50.0) - (high_count * 20.0))

        result = {
            "system_name": profile.name,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "risk_classification": risk_level.value,
            "compliance_score": score,
            "status": "APPROVED" if crit_count == 0 and score >= 80.0 else "NON_COMPLIANT_BLOCKED",
            "findings_count": len(findings),
            "findings": findings
        }

        # Cryptographic attestation digest of audit
        digest = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
        result["audit_attestation_hash"] = digest
        return result

