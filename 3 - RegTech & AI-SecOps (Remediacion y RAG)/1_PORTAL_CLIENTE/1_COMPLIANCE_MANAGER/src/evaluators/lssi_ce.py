#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lssi_ce.py - Evaluator for LSSI-CE (Ley 34/2002) y Guía de Cookies AEPD.
Auditing Aviso Legal (Art. 10), Política de Cookies (Art. 22.2), Anti-Spam (Art. 21) y DSA Takedowns.
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

class LSSICEEvaluator(BaseEvaluator):
    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "LSSI_CE_COOKIES_ES"

    def evaluate(self) -> EvaluatorResult:
        findings: list[Finding] = []
        target = Path(self.target_path)
        all_files: list[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. Aviso Legal Permanente (Art. 10 LSSI-CE)
        has_legal_notice = any(kw in f for f in all_files for kw in ["legal_notice", "aviso_legal", "art10", "cif"])
        findings.append(Finding(
            rule_id="ES-LSSI-NOTICE-001",
            framework=self.framework_name,
            title="Información General Permanente Obligatoria (Art. 10 LSSI-CE)",
            description="Acceso permanente, fácil, directo y gratuito a los datos identificativos (denominación social, NIF, domicilio, datos registrales mercantiles y contacto).",
            severity=Severity.HIGH,
            passed=has_legal_notice,
            evidence=f"Auditor o archivo de aviso legal mercantil detectado: {has_legal_notice}",
            remediation_guidance="Publicar aviso legal accesible con datos mercantiles completos conforme al Art. 10 LSSI-CE.",
            iso27001_mapping=["A.18.1.1"],
            soc2_mapping=["CC1.1"]
        ))

        # 2. Consentimiento de Cookies Guía AEPD (Art. 22.2 LSSI-CE)
        has_cookies = any(kw in f for f in all_files for kw in ["cookie", "aepd", "consent", "banner"])
        findings.append(Finding(
            rule_id="ES-LSSI-COOKIE-002",
            framework=self.framework_name,
            title="Consentimiento Granular de Cookies y Rastreadores conforme Guía AEPD (Art. 22.2)",
            description="Banner de cookies con botón 'Rechazar todo' al mismo nivel de visibilidad y facilidad que 'Aceptar todo', sin casillas premarcadas ni cookie walls abusivos.",
            severity=Severity.CRITICAL,
            passed=has_cookies,
            evidence=f"Mecanismo o auditor de consentimiento de cookies AEPD detectado: {has_cookies}",
            remediation_guidance="Incorporar botón de rechazar cookies en el primer nivel con visibilidad idéntica a aceptar.",
            iso27001_mapping=["A.18.1.4"],
            soc2_mapping=["CC6.1"]
        ))

        # 3. Comunicaciones Comerciales y Anti-Spam (Art. 21 LSSI-CE)
        has_anti_spam = any(kw in f for f in all_files for kw in ["spam", "opt_in", "comunicaciones", "unsubscribe"])
        findings.append(Finding(
            rule_id="ES-LSSI-SPAM-003",
            framework=self.framework_name,
            title="Prohibición de Comunicaciones Comerciales No Solicitadas (Art. 21 LSSI-CE)",
            description="Prohibición de enviar comunicaciones publicitarias o promocionales por correo electrónico u otro medio telemático sin solicitud o autorización previa (doble opt-in).",
            severity=Severity.HIGH,
            passed=has_anti_spam,
            evidence=f"Mecanismo de doble opt-in o verificación anti-spam detectado: {has_anti_spam}",
            remediation_guidance="Establecer procedimiento de doble opt-in y baja automática en comunicaciones comerciales.",
            iso27001_mapping=["A.18.1.4"],
            soc2_mapping=["CC2.2"]
        ))

        # 4. Retirada de Contenidos Ilícitos (Arts. 13-17 LSSI / DSA)
        has_takedown = any(kw in f for f in all_files for kw in ["moderation", "takedown", "retirada", "dark_pattern", "dsa"])
        findings.append(Finding(
            rule_id="ES-LSSI-TAKEDOWN-004",
            framework=self.framework_name,
            title="Procedimiento Ágil de Notificación y Retirada de Contenidos Ilícitos",
            description="Régimen de responsabilidad e intermediación que garantiza la retirada o bloqueo diligente al adquirir conocimiento efectivo de contenidos ilícitos.",
            severity=Severity.HIGH,
            passed=has_takedown,
            evidence=f"Motor de moderación o procedimiento Notice-and-Action detectado: {has_takedown}",
            remediation_guidance="Implantar procedimiento ágil de retirada de contenidos ilícitos coordinado con el DSA.",
            iso27001_mapping=["A.16.1.5"],
            soc2_mapping=["CC7.3"]
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
            metrics={"statute": "Ley 34/2002 LSSI-CE (BOE-A-2002-13758)", "aepd_cookie_guide": "AEPD / CEPD Guidelines"}
        )
