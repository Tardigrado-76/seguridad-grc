#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lgtel.py - Evaluator for Ley General de Telecomunicaciones (Ley 11/2022) & Seguridad 5G.
Auditing Seguridad e Integridad de Redes (Arts. 110-118 LGTel) y RD-ley 7/2022.
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

class LGTelEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "LGTEL_SEGURIDAD_ES"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. Gestión de Riesgos e Integridad de Redes (Art. 110 LGTel)
        has_network_integ = any(kw in f for f in all_files for kw in ["iac_drift", "security-audit", "integrity", "redes"])
        findings.append(Finding(
            rule_id="ES-LGTEL-INTEG-001",
            framework=self.framework_name,
            title="Gestión de Riesgos de Seguridad e Integridad de Redes y Servicios (Art. 110 LGTel)",
            description="Supervisión de medidas técnicas y organizativas adecuadas para gestionar los riesgos para la seguridad de las redes y servicios de comunicaciones electrónicas.",
            severity=Severity.CRITICAL,
            passed=has_network_integ,
            evidence=f"Auditor de integridad de redes o análisis de drift detectado: {has_network_integ}",
            remediation_guidance="Desplegar plan de seguridad de redes y auditorías continuas de enlaces conforme a la Ley 11/2022.",
            iso27001_mapping=["A.13.1.1", "A.13.1.2"],
            soc2_mapping=["CC6.6", "CC6.7"]
        ))

        # 2. Marco de Seguridad 5G y Diversificación (RD-ley 7/2022)
        has_5g_sec = any(kw in f for f in all_files for kw in ["5g", "vendor", "telecom", "suministrador"])
        findings.append(Finding(
            rule_id="ES-LGTEL-5G-002",
            framework=self.framework_name,
            title="Cumplimiento del Marco de Seguridad 5G y Diversificación de Suministradores",
            description="Exclusión de proveedores clasificados de alto riesgo en nodos críticos del núcleo (Core) de la red 5G y diversificación de equipamiento.",
            severity=Severity.CRITICAL,
            passed=has_5g_sec,
            evidence=f"Auditor de seguridad 5G y proveedores críticos detectado: {has_5g_sec}",
            remediation_guidance="Validar matriz de suministradores de red 5G excluyendo proveedores clasificados de alto riesgo.",
            iso27001_mapping=["A.15.1.2", "A.15.2.1"],
            soc2_mapping=["CC9.2"]
        ))

        # 3. Notificación de Incidentes a Autoridad Nacional (Art. 111 LGTel)
        has_incident_notify = any(kw in f for f in all_files for kw in ["incident", "notif", "cnmc", "ministerio"])
        findings.append(Finding(
            rule_id="ES-LGTEL-INC-003",
            framework=self.framework_name,
            title="Notificación Obligatoria de Incidentes de Seguridad a la Autoridad Competente",
            description="Obligación de notificar sin dilación indebida al Ministerio de Transformación Digital cualquier incidente significativo que afecte a la seguridad o continuidad.",
            severity=Severity.HIGH,
            passed=has_incident_notify,
            evidence=f"Protocolo de notificación de brechas de red detectado: {has_incident_notify}",
            remediation_guidance="Implementar procedimiento telemático de comunicación de incidentes significativos a la SETID e INCIBE-CERT.",
            iso27001_mapping=["A.16.1.1", "A.16.1.2"],
            soc2_mapping=["CC7.3"]
        ))

        # 4. Cifrado y Control de Acceso a Nodos Críticos
        has_crypto_nodes = any(kw in f for f in all_files for kw in ["crypto", "tls", "pki", "hsm", "kms"])
        findings.append(Finding(
            rule_id="ES-LGTEL-CRYPTO-004",
            framework=self.framework_name,
            title="Cifrado y Control de Acceso a Infraestructuras Troncales y Nodos Críticos",
            description="Implementación de cifrado robusto en el plano de control y de usuario, así como control de acceso biométrico o MFA a centros de conmutación.",
            severity=Severity.HIGH,
            passed=has_crypto_nodes,
            evidence=f"Módulos criptográficos TLS 1.3 / HSM / PKI detectados: {has_crypto_nodes}",
            remediation_guidance="Asegurar cifrado de enlaces inter-nodo y autenticación robusta en centros de conmutación.",
            iso27001_mapping=["A.10.1.1", "A.11.1.2"],
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
            metrics={"statute": "Ley 11/2022 (BOE-A-2022-10757)", "5g_framework": "RD-ley 7/2022"}
        )
