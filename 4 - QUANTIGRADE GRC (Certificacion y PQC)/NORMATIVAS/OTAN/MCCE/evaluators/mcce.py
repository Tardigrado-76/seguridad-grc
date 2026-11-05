#!/usr/bin/env python3
"""
mcce.py - Evaluator for MCCE Military Cyberdefense & NATO Classified Information.
Audits EMAD/MCCE Directives, NATO STANAG 4774/4778 Metadata Binding,
CCN-STIC 400/500 Classified Information Systems, and Military WANDEF Air-Gaps.
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


class MCCEEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "MCCE_CIBERDEFENSA_MILITAR_OTAN"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. Directivas Operativas de Ciberdefensa y Enlace CSIRT Militar (MCCE)
        has_mcce_ops = any(kw in f for f in all_files for kw in ["mcce", "csirt_militar", "ciberdefensa", "emad", "operaciones_militares"])
        findings.append(Finding(
            rule_id="ES-MCCE-OPS-001",
            framework=self.framework_name,
            title="Directivas de Ciberdefensa Militar y Enlace Permanente con CSIRT Militar (MCCE)",
            description="Coordinación operativa continua con el Mando Conjunto del Ciberespacio y capacidad de reporte táctico en tiempo real.",
            severity=Severity.CRITICAL,
            passed=has_mcce_ops,
            evidence=f"Especificación de enlace o directiva operativa MCCE detectada: {has_mcce_ops}",
            remediation_guidance="Establecer canal seguro de enlace táctico con el CSIRT Militar del MCCE.",
            iso27001_mapping=["A.16.1.1", "A.16.1.2"],
            soc2_mapping=["CC7.3", "CC7.4"]
        ))

        # 2. Etiquetado Criptográfico STANAG 4774 / 4778 para Interoperabilidad OTAN
        has_stanag = any(kw in f for f in all_files for kw in ["stanag", "4774", "4778", "confidentiality_metadata", "nato_marking"])
        findings.append(Finding(
            rule_id="NATO-STANAG-4774-002",
            framework=self.framework_name,
            title="Marcado y Enlace Criptográfico de Metadatos de Confidencialidad (STANAG 4774 / 4778)",
            description="Encapsulamiento de metadatos de seguridad y clasificación conforme a estándares OTAN para intercambio seguro de información aliada.",
            severity=Severity.CRITICAL,
            passed=has_stanag,
            evidence=f"Ejemplo o validador de marcado STANAG 4774/4778 detectado: {has_stanag}",
            remediation_guidance="Integrar binding criptográfico de etiquetas STANAG 4774 en las estructuras de datos y reportes.",
            iso27001_mapping=["A.8.2", "A.8.3"],
            soc2_mapping=["CC6.1"]
        ))

        # 3. Acreditación de Sistemas para Información Clasificada (CCN-STIC 400 / 500)
        has_ccn_400 = any(kw in f for f in all_files for kw in ["clasificada", "ccn_stic_400", "difusion_limitada", "secreto", "acreditacion_seguridad"])
        findings.append(Finding(
            rule_id="ES-CCN-STIC-400-003",
            framework=self.framework_name,
            title="Acreditación de Sistemas para Manejo de Información Clasificada (Guías CCN-STIC 400/500)",
            description="Certificación y bastionado para tratamiento de materias clasificadas (Difusión Limitada, Confidencial, Reservado o Secreto).",
            severity=Severity.HIGH,
            passed=has_ccn_400,
            evidence=f"Acreditación o controles CCN-STIC 400 para información clasificada detectados: {has_ccn_400}",
            remediation_guidance="Aplicar las salvaguardas de la Guía CCN-STIC 401 y tramitar la acreditación ante la ONS/CCN.",
            iso27001_mapping=["A.18.1.3"],
            soc2_mapping=["CC6.3"]
        ))

        # 4. Aislamiento Táctico y Redes Militares Seguras (WANDEF / WANPG Air-Gap)
        has_airgap_mil = any(kw in f for f in all_files for kw in ["airgap", "wandef", "wanpg", "enclave_militar", "aislamiento_tactico"])
        findings.append(Finding(
            rule_id="ES-MCCE-AIRGAP-004",
            framework=self.framework_name,
            title="Aislamiento Táctico Air-Gap y Conectividad en Enclaves Militares (Redes WANDEF / WANPG)",
            description="Controles de segmentación estricta y desconexión galvánica de Internet para enclaves militares y puestos de mando.",
            severity=Severity.HIGH,
            passed=has_airgap_mil,
            evidence=f"Procedimientos de aislamiento y enclave militar seguro detectados: {has_airgap_mil}",
            remediation_guidance="Desplegar pasarelas unidireccionales (diodos de datos) y aislar las redes de operaciones de defensa.",
            iso27001_mapping=["A.13.1.1", "A.13.1.3"],
            soc2_mapping=["CC6.6"]
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
            metrics={"supervising_body": "MCCE / EMAD / OTAN", "standards": "STANAG 4774/4778, CCN-STIC 400"}
        )
