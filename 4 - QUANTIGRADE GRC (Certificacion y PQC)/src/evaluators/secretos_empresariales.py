#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secretos_empresariales.py - Evaluator for Ley de Secretos Empresariales (Ley 1/2019).
Auditing Medidas Razonables de Protección (Art. 1 Ley 1/2019), Directiva UE 2016/943 y DATA Act Safeguards.
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

class SecretosEmpresarialesEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "SECRETOS_EMPRESARIALES_ES"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. Medidas Razonables de Protección (Art. 1 Ley 1/2019)
        has_vault = any(kw in f for f in all_files for kw in ["secretos", "trade_secrets", "vault", "confidencial"])
        findings.append(Finding(
            rule_id="ES-SEC-VAULT-001",
            framework=self.framework_name,
            title="Medidas Técnicas Razonables de Protección de Secretos (Art. 1 Ley 1/2019)",
            description="Supervisión de medidas técnicas, organizativas y jurídicas adoptadas por el legítimo titular para mantener secreta la información confidencial o tecnológica.",
            severity=Severity.CRITICAL,
            passed=has_vault,
            evidence=f"Bóveda o sistema de protección técnica de secretos empresariales detectado: {has_vault}",
            remediation_guidance="Desplegar cifrado AES-256 e inventario clasificado de secretos industriales bajo la Ley 1/2019.",
            iso27001_mapping=["A.8.2.1", "A.8.2.2"],
            soc2_mapping=["CC6.1", "CC6.3"]
        ))

        # 2. Control de Acceso Restrictivo y Need-to-Know
        has_rbac = any(kw in f for f in all_files for kw in ["rbac", "access", "need_to_know", "privilege"])
        findings.append(Finding(
            rule_id="ES-SEC-RBAC-002",
            framework=self.framework_name,
            title="Control de Accesos Restrictivo y Principio de Necesidad de Conocer (Need-to-Know)",
            description="Políticas de acceso basadas en el mínimo privilegio con autenticación multifactor y compromisos de confidencialidad contractuales (NDA).",
            severity=Severity.HIGH,
            passed=has_rbac,
            evidence=f"Políticas de acceso restrictivo y acuerdos NDA detectados: {has_rbac}",
            remediation_guidance="Implementar RBAC estricto y vinculación técnica de acuerdos de confidencialidad a credenciales.",
            iso27001_mapping=["A.9.1.1", "A.9.2.6"],
            soc2_mapping=["CC6.2"]
        ))

        # 3. Trazabilidad Inmutable de Descargas y Accesos
        has_audit = any(kw in f for f in all_files for kw in ["audit", "download", "trazabilidad", "bunker"])
        findings.append(Finding(
            rule_id="ES-SEC-AUDIT-003",
            framework=self.framework_name,
            title="Trazabilidad Inmutable de Descargas y Divulgaciones de Información Confidencial",
            description="Registro auditable de cualquier acceso, copia, descarga o exportación de algoritmos, fórmulas o datos clasificados.",
            severity=Severity.HIGH,
            passed=has_audit,
            evidence=f"Mecanismo de trazabilidad o auditoría inmutable de accesos detectado: {has_audit}",
            remediation_guidance="Habilitar registro forense de descargas y marcas de agua en documentos confidenciales.",
            iso27001_mapping=["A.12.4.1", "A.12.4.2"],
            soc2_mapping=["CC7.2"]
        ))

        # 4. Salvaguardas en Compartición bajo el Data Act Europeo
        has_data_act_safeguard = any(kw in f for f in all_files for kw in ["data_act", "b2b", "sharing", "smart_contract"])
        findings.append(Finding(
            rule_id="ES-SEC-DATA-ACT-004",
            framework=self.framework_name,
            title="Salvaguardas Contractuales y Técnicas de Trade Secrets bajo el Data Act Europeo",
            description="Protección de secretos empresariales en escenarios de portabilidad e interoperabilidad B2B exigidos por el Reglamento (UE) 2023/2854 (Data Act, Arts. 4.6 y 5.8).",
            severity=Severity.HIGH,
            passed=has_data_act_safeguard,
            evidence=f"Módulos de intermediación B2B o salvaguardas Data Act detectados: {has_data_act_safeguard}",
            remediation_guidance="Establecer salvaguardas técnicas contractuales antes de transferir datos con secretos a terceros.",
            iso27001_mapping=["A.13.2.1", "A.13.2.4"],
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
            metrics={"legal_statute": "Ley 1/2019 (BOE-A-2019-2364)", "eu_directive": "Directiva (UE) 2016/943"}
        )
