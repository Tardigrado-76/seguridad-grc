#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aesia_ia.py - Evaluator for Gobernanza de IA en España (AESIA).
Auditing Real Decreto 817/2023 (Sandbox IA), Estatuto AESIA (RD 729/2023) and EU AI Act Alignment.
"""

from __future__ import annotations
import os
import sys
from pathlib import Path

BASE_DIR = Path(r"E:/PROYECTOS IA/AUDITORIAS/NUEVO ORDEN/1_PORTAL_CLIENTE/1_COMPLIANCE_MANAGER")
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.evaluators.base import (
    BaseEvaluator,
    EvaluatorResult,
    Finding,
    RAGStatus,
    Severity,
)

class AESIAGovernanceEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "AESIA_GOBERNANZA_IA_ES"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. AESIA Sandbox & RD 817/2023
        has_sandbox = any(kw in f for f in all_files for kw in ["sandbox", "aesia", "ai_compliance"])
        findings.append(Finding(
            rule_id="ES-AESIA-SANDBOX-001",
            framework=self.framework_name,
            title="Entorno Controlado de Pruebas y Directrices Técnicas AESIA (RD 817/2023)",
            description="Supervisión de sistemas de IA de alto riesgo en el marco del Sandbox español y el Estatuto de la Agencia Española de Supervisión de la IA (RD 729/2023).",
            severity=Severity.CRITICAL,
            passed=has_sandbox,
            evidence=f"Protocolo o motor de sandbox/compliance de IA detectado: {has_sandbox}",
            remediation_guidance="Formalizar la documentación técnica del Anexo IV y ficha descriptiva conforme a directrices de AESIA.",
            iso27001_mapping=["A.14.2.1", "A.14.2.5"],
            soc2_mapping=["CC6.8", "CC8.1"]
        ))

        # 2. FRIA adaptada al marco constitucional español
        has_fria = any(kw in f for f in all_files for kw in ["fria", "derechos_fundamentales", "bias", "sesgo"])
        findings.append(Finding(
            rule_id="ES-AESIA-FRIA-002",
            framework=self.framework_name,
            title="Evaluación de Impacto en Derechos Fundamentales (FRIA - Art. 27 AI Act / CE)",
            description="Evaluación del impacto del modelo algorítmico sobre los derechos fundamentales amparados por la Constitución Española (igualdad, intimidad y no discriminación).",
            severity=Severity.CRITICAL,
            passed=has_fria,
            evidence=f"Evaluador de impacto en derechos fundamentales (FRIA) detectado: {has_fria}",
            remediation_guidance="Realizar evaluación FRIA formal que documente mitigación de sesgos discriminatorios en datasets de entrenamiento.",
            iso27001_mapping=["A.18.1.4"],
            soc2_mapping=["CC3.2"]
        ))

        # 3. Supervisión Humana Efectiva (HITL)
        has_oversight = any(kw in f for f in all_files for kw in ["human_oversight", "hitl", "supervision_humana", "oversight"])
        findings.append(Finding(
            rule_id="ES-AESIA-OVERSIGHT-003",
            framework=self.framework_name,
            title="Supervisión Humana Efectiva (Human-in-the-Loop) y Auditoría Algorítmica",
            description="Garantía de intervención humana con potestad de anulación o parada de emergencia de decisiones algorítmicas de impacto crítico.",
            severity=Severity.HIGH,
            passed=has_oversight,
            evidence=f"Mecanismos de supervisión humana e intervención de parada de emergencia detectados: {has_oversight}",
            remediation_guidance="Habilitar capacidad técnica de veto humano y trazabilidad operativa de decisiones automáticas.",
            iso27001_mapping=["A.9.2.3", "A.12.1.1"],
            soc2_mapping=["CC6.3"]
        ))

        # 4. Marcado Criptográfico y Trazabilidad Sintética
        has_watermark = any(kw in f for f in all_files for kw in ["watermark", "provenance", "c2pa", "marcado"])
        findings.append(Finding(
            rule_id="ES-AESIA-WATERMARK-004",
            framework=self.framework_name,
            title="Marcado Criptográfico y Trazabilidad de Contenidos Sintéticos (Art. 50 AI Act / AESIA)",
            description="Inyección de marcas de agua y metadatos de procedencia C2PA criptográficamente verificables en cualquier contenido audiovisual o texto generado por IA.",
            severity=Severity.HIGH,
            passed=has_watermark,
            evidence=f"Motor de marcas de agua criptográficas o procedencia de modelos detectado: {has_watermark}",
            remediation_guidance="Incorporar marcado C2PA / marcas de agua verificables en salidas generativas del modelo.",
            iso27001_mapping=["A.10.1.1", "A.10.1.2"],
            soc2_mapping=["CC6.6", "CC6.7"]
        ))

        total_rules = len(findings)
        passed_rules = sum(1 for f in findings if f.passed)
        failed_rules = total_rules - passed_rules
        compliance_score = round((passed_rules / total_rules) * 100.0, 2)

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=compliance_score,
            rag_status=RAGStatus.GREEN if compliance_score >= 80.0 else (RAGStatus.AMBER if compliance_score >= 50.0 else RAGStatus.RED),
            total_rules=total_rules,
            passed_rules=passed_rules,
            failed_rules=failed_rules,
            findings=findings,
            metrics={"agency": "AESIA (A Coruña)", "sandbox_regulation": "RD 817/2023"}
        )
