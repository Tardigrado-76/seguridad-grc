#!/usr/bin/env python3
"""
dpp_customs.py - Evaluator for EU Digital Product Passport (ESPR 2024/1781) & EU Customs Data Hub Compliance.
Audits DPP GS1 Digital Links, EU Customs Data Hub Electronic Manifests, Conflict Minerals Due Diligence,
and eIDAS 2.0 Smart Seals.
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


class DPPCustomsEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "DPP_TRAZABILIDAD_ADUANERA_UE"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. Pasaporte Digital de Producto y Portador GS1 Digital Link (ESPR 2024/1781)
        has_dpp = any(kw in f for f in all_files for kw in ["dpp", "pasaporte_digital", "espr", "gs1_digital_link", "ecodiseno"])
        findings.append(Finding(
            rule_id="UE-DPP-ESPR-001",
            framework=self.framework_name,
            title="Pasaporte Digital de Producto con Portador GS1 Digital Link y Ecodiseño (Reglamento UE 2024/1781)",
            description="Existencia de portador de datos único (QR / GS1) y credenciales verificables con huella de carbono, durabilidad y composición del producto.",
            severity=Severity.CRITICAL,
            passed=has_dpp,
            evidence=f"Payload o especificación de pasaporte digital de producto detectada: {has_dpp}",
            remediation_guidance="Estructurar el DPP en formato W3C Verifiable Credential y enlazarlo con GS1 Digital Link.",
            iso27001_mapping=["A.8.12", "A.8.24"],
            soc2_mapping=["CC6.8"]
        ))

        # 2. Integración Telemática con el EU Customs Data Hub (CAU / UCC)
        has_customs = any(kw in f for f in all_files for kw in ["aduanas", "customs_hub", "manifiesto", "cau", "import_export"])
        findings.append(Finding(
            rule_id="UE-CUSTOMS-HUB-002",
            framework=self.framework_name,
            title="Integración Telemática y Manifiestos de Carga con el EU Customs Data Hub",
            description="Declaraciones electrónicas anticipadas de importación/exportación sincronizadas con la ventanilla única aduanera de la UE.",
            severity=Severity.HIGH,
            passed=has_customs,
            evidence=f"Manifiesto electrónico o integración con EU Customs Hub detectada: {has_customs}",
            remediation_guidance="Generar manifiestos electrónicos conformes con el esquema de datos del EU Customs Data Hub.",
            iso27001_mapping=["A.14.1.3"],
            soc2_mapping=["CC1.4"]
        ))

        # 3. Trazabilidad de Cadena de Custodia y Minerales de Conflicto (Reglamento UE 2017/821)
        has_provenance = any(kw in f for f in all_files for kw in ["provenance", "minerales_conflicto", "cadena_custodia", "due_diligence", "trazabilidad"])
        findings.append(Finding(
            rule_id="UE-DPP-PROVENANCE-003",
            framework=self.framework_name,
            title="Trazabilidad y Debida Diligencia de Cadena de Custodia de Minerales de Conflicto (UE 2017/821)",
            description="Verificación de no utilización de minerales procedentes de zonas de conflicto (3TG) mediante grafos de proveniencia inmutables.",
            severity=Severity.HIGH,
            passed=has_provenance,
            evidence=f"Evidencia de debida diligencia de cadena de custodia detectada: {has_provenance}",
            remediation_guidance="Auditar fundiciones y proveedores de materias primas según directrices de la OCDE.",
            iso27001_mapping=["A.15.1.1"],
            soc2_mapping=["CC9.2"]
        ))

        # 4. Precintos Inteligentes con Sellado Cualificado eIDAS 2.0 (RFC 3161)
        has_smart_seal = any(kw in f for f in all_files for kw in ["precinto", "smart_seal", "eidas", "qseal", "rfc3161"])
        findings.append(Finding(
            rule_id="UE-SMART-SEAL-004",
            framework=self.framework_name,
            title="Precintos Electrónicos Inteligentes Inmutables con Sellado eIDAS 2.0 (RFC 3161 / QSeal)",
            description="Protección física y lógica de contenedores y palets con sellos electrónicos cualificados para prevenir manipulación en tránsito aduanero.",
            severity=Severity.CRITICAL,
            passed=has_smart_seal,
            evidence=f"Evidencia de precinto electrónico eIDAS 2.0 detectada: {has_smart_seal}",
            remediation_guidance="Incorporar precintos electrónicos cualificados respaldados por Prestadores Cualificados de Servicios de Confianza (QTSP).",
            iso27001_mapping=["A.11.2.6"],
            soc2_mapping=["CC6.4"]
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
            metrics={"regulatory_frameworks": "ESPR 2024/1781, EU Customs Data Hub, eIDAS 2.0", "customs_union": "EU_27"}
        )
