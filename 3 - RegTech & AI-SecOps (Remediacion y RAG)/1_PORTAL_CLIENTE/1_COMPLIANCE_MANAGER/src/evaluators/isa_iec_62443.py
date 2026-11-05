#!/usr/bin/env python3
"""
isa_iec_62443.py - Evaluator for ISA/IEC 62443 Industrial Automation & Control Systems (IACS) Security.
Audits Zones & Conduits Segmentation (Part 3-2), Security Level SL-2+ (Part 3-3),
Industrial Protocol Hardening (Modbus/DNP3/Profinet), and Operational Patch Management (Part 2-3).
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


class ISAIEC62443Evaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "ISA_IEC_62443_CIBERSEGURIDAD_INDUSTRIAL_OT"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. Segmentación en Zonas y Conductos (IEC 62443-3-2)
        has_zones_conduits = any(kw in f for f in all_files for kw in ["zonas", "conductos", "zones", "conduits", "segmentacion_industrial"])
        findings.append(Finding(
            rule_id="IEC-62443-ZONES-001",
            framework=self.framework_name,
            title="Segmentación Formal en Zonas y Conductos Industriales (ISA/IEC 62443-3-2)",
            description="Particionado de la arquitectura OT en zonas de seguridad homogéneas comunicadas exclusivamente mediante conductos protegidos con DPI.",
            severity=Severity.CRITICAL,
            passed=has_zones_conduits,
            evidence=f"Arquitectura o mapa de segmentación en zonas y conductos detectado: {has_zones_conduits}",
            remediation_guidance="Definir zonas y conductos industriales con firewalls de inspección profunda según IEC 62443-3-2.",
            iso27001_mapping=["A.13.1.3"],
            soc2_mapping=["CC6.6"]
        ))

        # 2. Cumplimiento de Requisitos Fundamentales FR 1 a FR 7 (Security Level SL-2+)
        has_sl2 = any(kw in f for f in all_files for kw in ["security_level", "sl2", "sl3", "fr1_fr7", "nivel_seguridad"])
        findings.append(Finding(
            rule_id="IEC-62443-SL-002",
            framework=self.framework_name,
            title="Conformidad de Requisitos Fundamentales FR 1 a FR 7 para Nivel de Seguridad SL-2+ (Part 3-3)",
            description="Verificación de autenticación robusta, control de uso, integridad, confidencialidad, flujo restringido y alta disponibilidad en activos IACS.",
            severity=Severity.CRITICAL,
            passed=has_sl2,
            evidence=f"Matriz de conformidad de requisitos fundamentales FR 1 a FR 7 detectada: {has_sl2}",
            remediation_guidance="Implantar controles técnicos para alcanzar el nivel de seguridad objetivo SL-T 2 en toda la planta.",
            iso27001_mapping=["A.9.4.2", "A.12.1.2"],
            soc2_mapping=["CC6.1", "A1.2"]
        ))

        # 3. Hardening y Aislamiento de Protocolos Industriales No Cifrados
        has_proto_hardening = any(kw in f for f in all_files for kw in ["protocolo_industrial", "modbus", "dnp3", "profinet", "hardening_scada"])
        findings.append(Finding(
            rule_id="IEC-62443-PROTO-003",
            framework=self.framework_name,
            title="Hardening y Aislamiento de Protocolos Industriales Legacy (Modbus/DNP3/Profinet)",
            description="Protección frente a inyección de comandos no autorizados en buses de campo industriales mediante túneles cifrados y filtrado perimetral.",
            severity=Severity.HIGH,
            passed=has_proto_hardening,
            evidence=f"Evidencia de hardening y protección de protocolos industriales detectada: {has_proto_hardening}",
            remediation_guidance="Encapsular protocolos OT en túneles VPN/TLS y desplegar reglas DPI para comandos SCADA.",
            iso27001_mapping=["A.13.2.1"],
            soc2_mapping=["CC6.7"]
        ))

        # 4. Gestión de Parches y Resiliencia sin Parada Operativa (IEC 62443-2-3)
        has_patching = any(kw in f for f in all_files for kw in ["parches", "patch_management", "resiliencia_planta", "parada_operativa", "mantenimiento_ot"])
        findings.append(Finding(
            rule_id="IEC-62443-PATCH-004",
            framework=self.framework_name,
            title="Gestión de Parches en Sistemas IACS y Resiliencia Operativa Continua (Part 2-3)",
            description="Procedimientos formales para evaluación, prueba en gemelo digital y despliegue de parches de seguridad sin interrupción de servicios esenciales.",
            severity=Severity.HIGH,
            passed=has_patching,
            evidence=f"Procedimiento de gestión de parches industriales y resiliencia detectado: {has_patching}",
            remediation_guidance="Establecer ventanas de actualización probadas en gemelo digital con planes de reversión garantizados.",
            iso27001_mapping=["A.12.6.1"],
            soc2_mapping=["CC8.1"]
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
            metrics={"industrial_standard": "ISA/IEC 62443", "target_security_level": "SL-2+"}
        )
