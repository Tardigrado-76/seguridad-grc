#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lpic.py - Evaluator for Protección de Infraestructuras Críticas (Ley 8/2011 & RD 704/2011).
Auditing Plan de Seguridad del Operador (PSO), Plan de Protección Específico (PPE) y Enlace CNPIC.
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

class LPICEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "LPIC_INFRAESTRUCTURAS_CRITICAS_ES"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. Plan de Seguridad del Operador (PSO)
        has_pso = any(kw in f for f in all_files for kw in ["pso", "cnpic", "operador_critico", "lpic"])
        findings.append(Finding(
            rule_id="ES-LPIC-PSO-001",
            framework=self.framework_name,
            title="Plan de Seguridad del Operador (PSO) Aprobado ante CNPIC (Ley 8/2011 Art. 13)",
            description="Elaboración y actualización del Plan de Seguridad del Operador que define las políticas generales de seguridad física y lógica del operador crítico.",
            severity=Severity.CRITICAL,
            passed=has_pso,
            evidence=f"Documentación o motor de validación PSO detectado: {has_pso}",
            remediation_guidance="Elaborar Plan de Seguridad del Operador conforme a directrices del CNPIC.",
            iso27001_mapping=["A.5.1.1", "A.6.1.1"],
            soc2_mapping=["CC1.2", "CC1.3"]
        ))

        # 2. Planes de Protección Específicos (PPE)
        has_ppe = any(kw in f for f in all_files for kw in ["ppe", "especifico", "instalacion", "proteccion"])
        findings.append(Finding(
            rule_id="ES-LPIC-PPE-002",
            framework=self.framework_name,
            title="Planes de Protección Específicos (PPE) por Instalación Crítica (RD 704/2011 Art. 24)",
            description="Planes individualizados para cada una de las infraestructuras consideradas críticas que detallan las medidas de protección operativa y coordinación con las FCS.",
            severity=Severity.CRITICAL,
            passed=has_ppe,
            evidence=f"Planes PPE o medidas de protección por instalación detectadas: {has_ppe}",
            remediation_guidance="Desarrollar Planes de Protección Específicos para cada infraestructura catalogada como crítica.",
            iso27001_mapping=["A.11.1.1", "A.11.1.2"],
            soc2_mapping=["CC6.4"]
        ))

        # 3. Delegado de Seguridad y Enlace (RSO)
        has_rso = any(kw in f for f in all_files for kw in ["rso", "enlace", "csirt", "contacto"])
        findings.append(Finding(
            rule_id="ES-LPIC-RSO-003",
            framework=self.framework_name,
            title="Designación Oficial del Responsable de Seguridad y Enlace (RSO) ante CNPIC",
            description="Nombramiento y acreditación formal del RSO como punto de contacto permanente 24/7 entre el operador crítico y el Ministerio del Interior.",
            severity=Severity.HIGH,
            passed=has_rso,
            evidence=f"Registro o procedimientos de enlace RSO / CSIRT detectados: {has_rso}",
            remediation_guidance="Designar formalmente al Responsable de Seguridad y Enlace ante el CNPIC.",
            iso27001_mapping=["A.6.1.2"],
            soc2_mapping=["CC2.1"]
        ))

        # 4. Aislamiento Físico y Cibernético (Air-Gap y Resiliencia)
        has_airgap = any(kw in f for f in all_files for kw in ["air_gap", "bunker", "hardening", "backup"])
        findings.append(Finding(
            rule_id="ES-LPIC-AIRGAP-004",
            framework=self.framework_name,
            title="Controles de Aislamiento Físico y Cibernético (Air-Gap, MFA y Backups Inmutables)",
            description="Implantación de controles de aislamiento total (air-gap) para sistemas de control industrial (OT/SCADA) y copias de seguridad desconectadas para garantizar la supervivencia del servicio esencial.",
            severity=Severity.CRITICAL,
            passed=has_airgap,
            evidence=f"Controles de aislamiento air-gap / copias de seguridad inmutables detectados: {has_airgap}",
            remediation_guidance="Implantar air-gap en redes OT/SCADA y copias de seguridad desconectadas.",
            iso27001_mapping=["A.13.1.3", "A.12.3.1"],
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
            metrics={"supervising_body": "CNPIC (Ministerio del Interior)", "statute": "Ley 8/2011 (BOE-A-2011-7630)"}
        )
