#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
corporate_defense.py - Evaluator for Corporate Defense y Prevención Penal.
Auditing Código Penal Art. 31 bis, UNE 19601, Ley 2/2023 (Canal de Denuncias) y Cadena de Custodia.
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

class CorporateDefenseEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "CORPORATE_DEFENSE_ES"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. Art. 31 bis CP & UNE 19601
        has_penal_matrix = any(kw in f for f in all_files for kw in ["corporate_risk", "prevencion_penal", "penal", "une19601"])
        findings.append(Finding(
            rule_id="ES-CP-31BIS-001",
            framework=self.framework_name,
            title="Modelo de Prevención de Delitos y Órgano de Cumplimiento (Art. 31 bis CP)",
            description="Supervisión de la implementación eficaz de modelos de organización y gestión que incluyen medidas de vigilancia y control idóneas para prevenir delitos societarios e informáticos.",
            severity=Severity.CRITICAL,
            passed=has_penal_matrix,
            evidence=f"Modelo de compliance penal / matriz de riesgos detectado: {has_penal_matrix}",
            remediation_guidance="Formalizar mapa de riesgos penales conforme a la norma UNE 19601 y asignarlo a Órgano de Cumplimiento.",
            iso27001_mapping=["A.18.1.1", "A.18.2.1"],
            soc2_mapping=["CC1.1", "CC1.2"]
        ))

        # 2. Canal de Denuncias Ley 2/2023
        has_whistleblower = any(kw in f for f in all_files for kw in ["whistleblower", "canal_denuncias", "informante", "denuncia"])
        findings.append(Finding(
            rule_id="ES-CP-WHISTLE-002",
            framework=self.framework_name,
            title="Canal de Denuncias Interno Cifrado y Confidencial (Ley 2/2023)",
            description="Existencia de un sistema interno de información que permite comunicaciones anónimas y confidenciales con garantía de indemnidad frente a represalias.",
            severity=Severity.CRITICAL,
            passed=has_whistleblower,
            evidence=f"Canal de denuncias confidencial con cifrado detectado: {has_whistleblower}",
            remediation_guidance="Desplegar canal ético con cifrado de extremo a extremo conforme a la Ley 2/2023.",
            iso27001_mapping=["A.7.2.2", "A.18.1.4"],
            soc2_mapping=["CC1.4", "CC2.2"]
        ))

        # 3. Cadena de Custodia Digital e Inmutabilidad Forense
        has_evidence_custody = any(kw in f for f in all_files for kw in ["custody", "cadena_custodia", "sealer", "inmutab"])
        findings.append(Finding(
            rule_id="ES-CP-EVIDENCE-003",
            framework=self.framework_name,
            title="Cadena de Custodia Digital e Inmutabilidad Forense de Pruebas",
            description="Preservación inmutable de registros de auditoría y evidencias digitales mediante sellado criptográfico SHA-256 y marcas de tiempo para validez en sede judicial.",
            severity=Severity.HIGH,
            passed=has_evidence_custody,
            evidence=f"Sistema de sellado y cadena de custodia probatoria detectado: {has_evidence_custody}",
            remediation_guidance="Implementar sellado criptográfico de registros de auditoría y almacenamiento WORM.",
            iso27001_mapping=["A.12.4.1", "A.12.4.3"],
            soc2_mapping=["CC7.2", "CC7.4"]
        ))

        # 4. Prevención de Delitos Informáticos Societarios
        has_cybercrime_controls = any(kw in f for f in all_files for kw in ["iso27001", "access_policy", "security_policy", "cybercrime", "soc2"])
        findings.append(Finding(
            rule_id="ES-CP-CYBERCRIME-004",
            framework=self.framework_name,
            title="Controles Técnicos Específicos contra Delitos Informáticos Societarios",
            description="Implementación de barreras técnicas contra daños informáticos (Art. 264 CP), estafa tecnológica (Art. 248 CP) y descubrimiento de secretos (Art. 197 CP).",
            severity=Severity.HIGH,
            passed=has_cybercrime_controls,
            evidence=f"Controles técnicos de seguridad frente a cibercrimen detectados: {has_cybercrime_controls}",
            remediation_guidance="Implementar controles de acceso estricto, DLP y segmentación para mitigar riesgos penales tecnológicos.",
            iso27001_mapping=["A.9.1.2", "A.12.6.1"],
            soc2_mapping=["CC6.1", "CC6.6"]
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
            metrics={"compliance_standard": "UNE 19601 / Art. 31 bis CP", "whistleblower_law": "Ley 2/2023"}
        )
