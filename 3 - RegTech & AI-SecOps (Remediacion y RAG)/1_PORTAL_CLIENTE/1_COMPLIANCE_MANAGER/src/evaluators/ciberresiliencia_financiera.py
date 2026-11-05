#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ciberresiliencia_financiera.py - Evaluator for Ciberresiliencia Financiera en España.
Auditing Banco de España TIBER-ES framework, Circular 2/2020, CNMV Guidelines, and DORA Integration.
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

class CiberresilienciaFinancieraEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "CIBERRESILIENCIA_FINANCIERA_ES"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. TIBER-ES Ethical Red Teaming
        has_tiber = any(kw in f for f in all_files for kw in ["tiber", "tlpt", "red_team"])
        findings.append(Finding(
            rule_id="ES-FIN-TIBER-001",
            framework=self.framework_name,
            title="Marco TIBER-ES de Pruebas de Resiliencia Basadas en Inteligencia de Amenazas",
            description="Evaluación de la ejecución de ejercicios de Ethical Red Teaming basados en amenazas reales (TIBER-ES) supervisados por Banco de España y el BCE.",
            severity=Severity.CRITICAL,
            passed=has_tiber,
            evidence=f"Evidencias de protocolo TIBER-ES / TLPT detectadas: {has_tiber}",
            remediation_guidance="Implementar protocolo TIBER-ES y remitir informes de remediación a Banco de España.",
            iso27001_mapping=["A.14.2.8", "A.12.6.1"],
            soc2_mapping=["CC7.1", "CC7.3"]
        ))

        # 2. Banco de España Continuidad y Ciberresiliencia
        has_bde_resilience = any(kw in f for f in all_files for kw in ["failover", "bde", "resilience", "contingencia"])
        findings.append(Finding(
            rule_id="ES-FIN-BDE-002",
            framework=self.framework_name,
            title="Requisitos de Ciberresiliencia y Continuidad Técnica (Banco de España)",
            description="Supervisión de planes de continuidad técnica, tiempos de recuperación RTO < 2h y RPO = 0 para sistemas de pago e infraestructuras financieras críticas.",
            severity=Severity.HIGH,
            passed=has_bde_resilience,
            evidence=f"Módulos de resiliencia y planes de contingencia técnica detectados: {has_bde_resilience}",
            remediation_guidance="Actualizar anualmente los planes de contingencia tecnológica aprobados por el Consejo de Administración.",
            iso27001_mapping=["A.17.1.1", "A.17.1.2"],
            soc2_mapping=["A1.2", "A1.3"]
        ))

        # 3. CNMV ICT Governance
        has_cnmv_cloud = any(kw in f for f in all_files for kw in ["cloud_exit", "third_party", "cnmv", "proveedores"])
        findings.append(Finding(
            rule_id="ES-FIN-CNMV-003",
            framework=self.framework_name,
            title="Directrices de la CNMV para Proveedores TIC Críticos y Cloud Services",
            description="Supervisión del registro de contratos con terceros tecnológicos y planes de salida de la nube (Cloud Exit Strategies) en entidades del mercado de valores.",
            severity=Severity.HIGH,
            passed=has_cnmv_cloud,
            evidence=f"Estrategias de salida multicloud y registro de terceros TIC detectados: {has_cnmv_cloud}",
            remediation_guidance="Revisar anualmente las cláusulas de auditoría y derecho de acceso con proveedores cloud esenciales.",
            iso27001_mapping=["A.15.1.1", "A.15.2.1"],
            soc2_mapping=["CC9.2"]
        ))

        # 4. Immediate Incident Reporting to Banco de España & CSIRT Financiero
        has_incident_report = any(kw in f for f in all_files for kw in ["incident_classifier", "incident_reporter", "nca", "csirt"])
        findings.append(Finding(
            rule_id="ES-FIN-INC-004",
            framework=self.framework_name,
            title="Notificación Inmediata de Incidentes Graves de Ciberseguridad a Autoridades Nacionales",
            description="Procedimiento formal de escalado y notificación de incidentes graves a Banco de España, CNMV y CSIRT Financiero dentro de los límites estipulados.",
            severity=Severity.CRITICAL,
            passed=has_incident_report,
            evidence=f"Canal y procedimiento de reporte de incidentes detectados: {has_incident_report}",
            remediation_guidance="Ejecutar simulacros periódicos de reporte de incidentes graves a los reguladores nacionales.",
            iso27001_mapping=["A.16.1.1", "A.16.1.2"],
            soc2_mapping=["CC7.3", "CC7.4"]
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
            metrics={"regulatory_authority": "Banco de España / CNMV", "tiber_es_status": "VALIDATED" if has_tiber else "MISSING"}
        )
