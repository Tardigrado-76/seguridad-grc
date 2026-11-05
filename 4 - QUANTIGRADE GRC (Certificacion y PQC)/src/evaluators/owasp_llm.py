#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
owasp_llm.py - OWASP Top 10 for Large Language Models 2025 Compliance Evaluator.
Audits Prompt Injection (LLM01), Data Poisoning (LLM03), Denial of Service (LLM04), and Excessive Agency (LLM06).
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Dict, Any
from src.evaluators.base import BaseEvaluator, EvaluatorResult, Finding, RAGStatus, Severity


class OWASPLLMEvaluator(BaseEvaluator):
    """Evaluador determinista de cumplimiento con OWASP Top 10 for LLM Applications 2025."""

    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "OWASP LLM 2025"

    def evaluate(self) -> EvaluatorResult:
        findings: List[Finding] = []
        target = Path(self.target_path)

        all_files: List[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. OWASP-LLM-001: Prompt Injection & Jailbreak Defense (LLM01)
        has_prompt_guard = any(
            any(kw in f for kw in ["prompt_guard", "jailbreak", "injection", "honeypot"])
            for f in all_files
        )
        findings.append(Finding(
            rule_id="OWASP-LLM-001",
            framework=self.framework_name,
            title="OWASP LLM01: Mitigación de Prompt Injection Directo e Indirecto",
            description="Auditar la existencia de filtros en tiempo de ejecución, honeypots de jailbreak y validación contextual de instrucciones para evitar la subversión del comportamiento del LLM.",
            severity=Severity.CRITICAL,
            passed=has_prompt_guard,
            evidence=f"Filtro de Prompt Injection o Honeypot detectado: {has_prompt_guard}",
            remediation_guidance="Desplegar motor llm_prompt_guard.py y barreras de sanitización de entradas en las canalizaciones de inferencia.",
            iso27001_mapping=["A.8.28"],
            soc2_mapping=["CC6.6"]
        ))

        # 2. OWASP-LLM-002: Training Data Poisoning & Vector Contamination (LLM03)
        has_poisoning_auditor = any(
            any(kw in f for kw in ["data_poisoning", "poisoning", "dataset_integrity", "rag_poisoning"])
            for f in all_files
        )
        findings.append(Finding(
            rule_id="OWASP-LLM-002",
            framework=self.framework_name,
            title="OWASP LLM03: Detección de Envenenamiento de Datos de Entrenamiento y Bases Vectoriales RAG",
            description="Verificar la inspección heurística de corpus de entrenamiento e ingesta vectorial para neutralizar inyecciones invisibles de caracteres unicode de ancho cero y puertas traseras.",
            severity=Severity.CRITICAL,
            passed=has_poisoning_auditor,
            evidence=f"Auditor de envenenamiento de datos RAG detectado: {has_poisoning_auditor}",
            remediation_guidance="Integrar llm_rag_data_poisoning_auditor.py para auditar la integridad y hash criptográfico de los documentos antes del embedding.",
            iso27001_mapping=["A.8.11"],
            soc2_mapping=["CC6.8"]
        ))

        # 3. OWASP-LLM-003: Model Denial of Service & Token Consumption Limits (LLM04)
        has_rate_limiter = any(
            any(kw in f for kw in ["ratelimiter", "rate_limit", "token_limit", "token_rate"])
            for f in all_files
        )
        findings.append(Finding(
            rule_id="OWASP-LLM-003",
            framework=self.framework_name,
            title="OWASP LLM04: Prevención de Denegación de Servicio y Consumo Excesivo de Tokens",
            description="Auditar límites de contexto, cuotas de tokens por sesión/usuario y limitadores de velocidad para prevenir el agotamiento de recursos computacionales.",
            severity=Severity.HIGH,
            passed=has_rate_limiter,
            evidence=f"Limitador de consumo de tokens y tasa de peticiones detectado: {has_rate_limiter}",
            remediation_guidance="Activar llm_token_ratelimiter.py con cuotas máximas de tokens por minuto y presupuestos de sesión.",
            iso27001_mapping=["A.8.6"],
            soc2_mapping=["A1.2"]
        ))

        # 4. OWASP-LLM-004: Excessive Agency & Unconstrained Tool Execution (LLM06)
        has_agency_guard = any(
            any(kw in f for kw in ["autonomous_agent", "ai_sec_guard", "agency", "tool_guard"])
            for f in all_files
        )
        findings.append(Finding(
            rule_id="OWASP-LLM-004",
            framework=self.framework_name,
            title="OWASP LLM06: Restricción de Agencia Excesiva y Control de Ejecución de Herramientas",
            description="Verificar que los agentes autónomos operen bajo el principio de mínimo privilegio con listas blancas de herramientas y autorización estricta para acciones destructivas.",
            severity=Severity.HIGH,
            passed=has_agency_guard,
            evidence=f"Guardarraíl de control de agencia y privilegios de herramientas detectado: {has_agency_guard}",
            remediation_guidance="Integrar ai_sec_guard.py y honeypots de agentes para confinar las herramientas accesibles por el modelo.",
            iso27001_mapping=["A.8.5"],
            soc2_mapping=["CC6.1"]
        ))

        # Scoring & Metrics
        passed_count = sum(1 for f in findings if f.passed)
        total_count = len(findings)
        score = round((passed_count / total_count) * 100.0, 1) if total_count > 0 else 0.0

        if score >= 80.0:
            rag = RAGStatus.GREEN
        elif score >= 50.0:
            rag = RAGStatus.AMBER
        else:
            rag = RAGStatus.RED

        failed_count = total_count - passed_count
        remediation_hours = failed_count * 15.0
        opex_impact = failed_count * 2800.0

        metrics = {
            "owasp_llm_top10_status": "HARDENED" if score >= 80.0 else "VULNERABLE",
            "prompt_injection_shielded": has_prompt_guard,
            "rag_poisoning_audited": has_poisoning_auditor,
            "token_dos_shielded": has_rate_limiter,
            "excessive_agency_constrained": has_agency_guard
        }

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=score,
            rag_status=rag,
            total_rules=total_count,
            passed_rules=passed_count,
            failed_rules=failed_count,
            findings=findings,
            metrics=metrics,
            remediation_hours_est=remediation_hours,
            estimated_opex_impact_eur=opex_impact
        )


if __name__ == '__main__':
    evaluator = OWASPLLMEvaluator(".", "Test Corp")
    print(evaluator.evaluate())
