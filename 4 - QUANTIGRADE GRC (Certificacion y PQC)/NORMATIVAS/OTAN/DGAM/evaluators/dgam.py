#!/usr/bin/env python3
"""
dgam.py - Evaluator for DGAM & OTAN Defense Procurement Compliance.
Audits PECAL 2110 / 2210 Software Quality Assurance, REDGAM Registration,
Mission Critical Resilience, and Sovereign Defense Supply Chain.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(r"e:/PROYECTOS IA/PRODUCTION READY/100/GITHUB/QUANTIGRADE GRC")
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.evaluators.base import (
    BaseEvaluator,
    EvaluatorResult,
    Finding,
    RAGStatus,
    Severity,
)


class DGAMEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "DGAM_PECAL_DEFENSA_ES"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. PECAL 2110 / 2210 Software Quality Assurance
        has_pecal = any(kw in f for f in all_files for kw in ["pecal", "aqap", "pacs", "calidad_defensa"])
        findings.append(Finding(
            rule_id="ES-DGAM-PECAL-001",
            framework=self.framework_name,
            title="Aseguramiento de Calidad de Software Militar (PECAL 2110 / PECAL 2210)",
            description="Acreditación formal del Plan de Aseguramiento de la Calidad del Software (PACS) y cumplimiento de estándares OTAN AQAP.",
            severity=Severity.CRITICAL,
            passed=has_pecal,
            evidence=f"Evidencia o política de calidad PECAL detectada: {has_pecal}",
            remediation_guidance="Elaborar el PACS conforme a PECAL 2210 Ed.2 y someterlo a inspección GQAR.",
            iso27001_mapping=["A.8.25", "A.8.28"],
            soc2_mapping=["CC8.1"]
        ))

        # 2. Homologación en Registro REDGAM
        has_redgam = any(kw in f for f in all_files for kw in ["redgam", "homologacion", "registro_empresas", "dgam_cert"])
        findings.append(Finding(
            rule_id="ES-DGAM-REDGAM-002",
            framework=self.framework_name,
            title="Inscripción y Homologación en el Registro de Empresas de la DGAM (REDGAM)",
            description="Inscripción vigente en el REDGAM (Orden DEF/877/2014) como contratista homologado de armamento y material de defensa.",
            severity=Severity.CRITICAL,
            passed=has_redgam,
            evidence=f"Certificado o registro oficial REDGAM detectado: {has_redgam}",
            remediation_guidance="Formalizar la solicitud de inscripción y certificado de contratista en el REDGAM.",
            iso27001_mapping=["A.5.1"],
            soc2_mapping=["CC1.1"]
        ))

        # 3. Resiliencia de Sistemas de Misión Crítica (AAP-20/48)
        has_mission_crit = any(kw in f for f in all_files for kw in ["mision", "critica", "resiliencia", "aap", "tolerancia_fallos"])
        findings.append(Finding(
            rule_id="ES-DGAM-CRIT-003",
            framework=self.framework_name,
            title="Resiliencia Operacional en Sistemas de Misión Crítica Militar (AAP-20 / AAP-48)",
            description="Verificación de diseño tolerante a fallos, degradación grácil y redundancia ante ciberataques en teatros de operaciones.",
            severity=Severity.HIGH,
            passed=has_mission_crit,
            evidence=f"Matrices de resiliencia y pruebas de misión crítica militar detectadas: {has_mission_crit}",
            remediation_guidance="Implantar arquitectura de redundancia activa y pruebas de inyección de fallos según AAP-48.",
            iso27001_mapping=["A.8.14", "A.8.29"],
            soc2_mapping=["A1.2"]
        ))

        # 4. Cadena de Suministro Soberana Nacional / OTAN
        has_sovereign_supply = any(kw in f for f in all_files for kw in ["soberan", "cadena_suministro", "supply", "proveedor_otan", "vetado"])
        findings.append(Finding(
            rule_id="ES-DGAM-SUPPLY-004",
            framework=self.framework_name,
            title="Trazabilidad y Soberanía en la Cadena de Suministro Militar (Cero Componentes Vetados)",
            description="Auditoría de proveniencia del 100% de dependencias hardware y software, garantizando origen exclusivo en España o países OTAN.",
            severity=Severity.HIGH,
            passed=has_sovereign_supply,
            evidence=f"Auditoría de soberanía en la cadena de suministro detectada: {has_sovereign_supply}",
            remediation_guidance="Auditar el SBOM y excluir componentes o subcontratistas procedentes de países no autorizados.",
            iso27001_mapping=["A.5.19", "A.5.20"],
            soc2_mapping=["CC9.2"]
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
            metrics={"supervising_body": "DGAM (Ministerio de Defensa)", "quality_standard": "PECAL 2110 / 2210"}
        )
