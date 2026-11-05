#!/usr/bin/env python3
"""
itar_ear.py - Evaluator for ITAR (22 CFR 120-130), EAR (15 CFR 730-774),
and EU Dual-Use Regulation (EU) 2021/821 Annex I Compliance.
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


class ITAREAREvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "ITAR_EAR_DUAL_USE_EXPORT_CONTROL"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. ITAR USML Technical Data Access Control (22 CFR §120.10)
        has_itar = any(kw in f for f in all_files for kw in ["itar", "usml", "defense_article", "technical_data", "foreign_person"])
        findings.append(Finding(
            rule_id="US-ITAR-USML-001",
            framework=self.framework_name,
            title="Control de Acceso y Segregación a Datos Técnicos USML (ITAR 22 CFR §120.10)",
            description="Restricción estricta de acceso lógico y físico a artículos de defensa y datos técnicos de la lista USML para personal no habilitado.",
            severity=Severity.CRITICAL,
            passed=has_itar,
            evidence=f"Registro o política de control de acceso a datos técnicos ITAR detectado: {has_itar}",
            remediation_guidance="Implantar segregación lógica y controles de identidad basados en habilitación y nacionalidad autorizada.",
            iso27001_mapping=["A.9.1", "A.9.2"],
            soc2_mapping=["CC6.1", "CC6.2"]
        ))

        # 2. EAR Commerce Control List (CCL) & ECCN Classification (15 CFR §730-774)
        has_ear = any(kw in f for f in all_files for kw in ["ear", "ccl", "eccn", "commerce_control", "licensing"])
        findings.append(Finding(
            rule_id="US-EAR-CCL-002",
            framework=self.framework_name,
            title="Clasificación ECCN y Régimen de Licenciamiento EAR (15 CFR §730-774)",
            description="Clasificación formal de partidas bajo la Commerce Control List (CCL), validación de excepciones de licencia ENC y no distribución ilícita.",
            severity=Severity.HIGH,
            passed=has_ear,
            evidence=f"Ficha de clasificación ECCN o licencia EAR detectada: {has_ear}",
            remediation_guidance="Elaborar la ficha formal de clasificación ECCN y registrar excepciones de licencia aplicables.",
            iso27001_mapping=["A.8.24"],
            soc2_mapping=["CC6.6"]
        ))

        # 3. Reglamento (UE) 2021/821 Control de Doble Uso (Anexo I)
        has_dual_use = any(kw in f for f in all_files for kw in ["dual_use", "doble_uso", "reglamento_821", "annex_i", "ue_821"])
        findings.append(Finding(
            rule_id="UE-DUALUSE-821-003",
            framework=self.framework_name,
            title="Cumplimiento del Reglamento (UE) 2021/821 para Criptografía e IA de Doble Uso",
            description="Auditoría de software y hardware clasificados en el Anexo I del Reglamento UE 2021/821, con verificación de autorizaciones de exportación.",
            severity=Severity.CRITICAL,
            passed=has_dual_use,
            evidence=f"Auditoría o trazabilidad de productos de doble uso detectada: {has_dual_use}",
            remediation_guidance="Obtener la Autorización General de Exportación de la UE (EU001) o individual según corresponda.",
            iso27001_mapping=["A.18.1.1"],
            soc2_mapping=["CC1.4"]
        ))

        # 4. Cifrado FIPS 140-3 y Soberanía Cero Acceso Foráneo (Zero Foreign Access)
        has_crypto_sovereignty = any(kw in f for f in all_files for kw in ["crypto", "fips_140_3", "soberania_claves", "zero_foreign", "cifrado"])
        findings.append(Finding(
            rule_id="DEF-SEC-CRYPTO-004",
            framework=self.framework_name,
            title="Cifrado FIPS 140-3 y Soberanía Cero Acceso Foráneo (Zero Foreign Access)",
            description="Protección criptográfica robusta en reposo y tránsito con custodia soberana de claves sin injerencia ni acceso de proveedores extraterritoriales.",
            severity=Severity.HIGH,
            passed=has_crypto_sovereignty,
            evidence=f"Controles de cifrado FIPS 140-3 y custodia soberana detectados: {has_crypto_sovereignty}",
            remediation_guidance="Custodiar claves exclusivamente en HSMs soberanos con destrucción segura y modo FIPS 140-3.",
            iso27001_mapping=["A.10.1.1", "A.10.1.2"],
            soc2_mapping=["CC6.7"]
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
            metrics={"supervising_bodies": "US DDTC / US BIS / Secretaría de Estado de Comercio UE", "regulations": "ITAR, EAR, Reglamento UE 2021/821"}
        )
