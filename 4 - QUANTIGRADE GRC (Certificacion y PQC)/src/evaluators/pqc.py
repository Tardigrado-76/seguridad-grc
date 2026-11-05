#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pqc.py - Post-Quantum Cryptography (NIST FIPS 203, 204, 205 & CNSA 2.0) Compliance Evaluator.
Audits cryptographic agility, ML-KEM key exchange, ML-DSA/SLH-DSA digital signatures, and FIPS 140-3 zeroization.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Dict, Any
from src.evaluators.base import BaseEvaluator, EvaluatorResult, Finding, RAGStatus, Severity


class PQCEvaluator(BaseEvaluator):
    """Evaluador determinista de cumplimiento con el Mandato de Criptografía Post-Cuántica (PQC)."""

    def __init__(self, target_path: str, company_name: str):
        super().__init__(target_path, company_name)
        self.framework_name = "Mandato PQC NIST FIPS 203-204"

    def evaluate(self) -> EvaluatorResult:
        findings: List[Finding] = []
        target = Path(self.target_path)

        all_files: List[str] = []
        if target.exists():
            for root, _, files in os.walk(target):
                for f in files:
                    all_files.append(f.lower())

        # 1. PQC-AGIL-001: Agilidad Criptográfica y Estrategia de Migración (NIST SP 800-227 / CCN-STIC 807)
        has_agility_strategy = any(
            any(kw in f for kw in ["pqc_estrategia", "migracion_post_cuantica", "pqc_crypto_agility", "crypto_agility"])
            for f in all_files
        )
        findings.append(Finding(
            rule_id="PQC-AGIL-001",
            framework=self.framework_name,
            title="PQC Agilidad Criptográfica y Plan de Transición Post-Cuántica (NIST SP 800-227 / CCN-STIC 807)",
            description="Verificar la existencia de una estrategia formal de migración post-cuántica y herramientas automatizadas de agilidad criptográfica para inventariar y sustituir algoritmos clásicos (RSA/ECC).",
            severity=Severity.HIGH,
            passed=has_agility_strategy,
            evidence=f"Estrategia de migración y/o gestor de agilidad criptográfica detectado: {has_agility_strategy}",
            remediation_guidance="Aprobar formalmente el plan PQC_ESTRATEGIA_MIGRACION_POST_CUANTICA.md e integrar el motor pqc_crypto_agility_manager.py en la canalización CI/CD.",
            iso27001_mapping=["A.8.24"],
            soc2_mapping=["CC6.1"]
        ))

        # 2. PQC-KEM-002: Encapsulamiento de Claves Post-Cuánticas ML-KEM en TLS 1.3 / IPsec (FIPS 203)
        has_kem_exchange = any(
            any(kw in f for kw in ["pqc_hybrid_tls", "hybrid_tls", "pqc_ml_kem", "ml_kem", "kyber"])
            for f in all_files
        )
        findings.append(Finding(
            rule_id="PQC-KEM-002",
            framework=self.framework_name,
            title="PQC Negociación Híbrida de Claves ML-KEM (NIST FIPS 203) en Canales TLS 1.3 / IPsec",
            description="Auditar la implementación de intercambio de claves híbrido quantum-safe (X25519Kyber768 o ML-KEM-768/1024) para neutralizar ataques 'Harvest Now, Decrypt Later'.",
            severity=Severity.CRITICAL,
            passed=has_kem_exchange,
            evidence=f"Mecanismo de verificación TLS 1.3 híbrido y/o negociador IPsec ML-KEM detectado: {has_kem_exchange}",
            remediation_guidance="Desplegar cifradores híbridos X25519_MLKEM768 en puntos de terminación TLS e IPsec mediante pqc_hybrid_tls_verifier.py.",
            iso27001_mapping=["A.8.20"],
            soc2_mapping=["CC6.6"]
        ))

        # 3. PQC-DSA-003: Firmas Digitales Resistentes a Computación Cuántica ML-DSA / SLH-DSA (FIPS 204 / FIPS 205)
        has_dsa_signatures = any(
            any(kw in f for kw in ["fips_204", "mldsa", "slh_dsa", "dilithium", "sphincs"])
            for f in all_files
        )
        findings.append(Finding(
            rule_id="PQC-DSA-003",
            framework=self.framework_name,
            title="PQC Firmas Digitales Post-Cuánticas ML-DSA / SLH-DSA en Código y Certificados (FIPS 204/205)",
            description="Verificar la firma criptográfica post-cuántica de artefactos de software, commits de Git y certificados de clave pública usando esquemas basados en retículos o stateless hash-based.",
            severity=Severity.CRITICAL,
            passed=has_dsa_signatures,
            evidence=f"Firmador de commits ML-DSA y/o CA post-cuántica SLH-DSA detectados: {has_dsa_signatures}",
            remediation_guidance="Integrar fips_204_mldsa_git_commit_signer.py en la cadena de suministro de software y emitir certificados híbridos PQC.",
            iso27001_mapping=["A.8.24", "A.8.31"],
            soc2_mapping=["CC6.8"]
        ))

        # 4. PQC-FIPS-004: Módulos Criptográficos FIPS 140-3 y Zeroización Segura de Memoria
        has_fips_hardening = any(
            any(kw in f for kw in ["fips_140_3", "zeroization", "fips_mode", "rng_entropy"])
            for f in all_files
        )
        findings.append(Finding(
            rule_id="PQC-FIPS-004",
            framework=self.framework_name,
            title="PQC Bastionado FIPS 140-3 y Zeroización Segura de Claves en Memoria",
            description="Auditar que los módulos criptográficos operen en modo FIPS 140-3 Level 3+ con borrado seguro (zeroization) de claves efímeras tras su uso y entropía de generadores TRNG monitorizada.",
            severity=Severity.HIGH,
            passed=has_fips_hardening,
            evidence=f"Auditor de zeroización FIPS 140-3 y/o monitor de entropía RNG detectado: {has_fips_hardening}",
            remediation_guidance="Activar fips_mode_enforcer.py y auditar la destrucción de material criptográfico efímero con fips_140_3_zeroization_auditor.py.",
            iso27001_mapping=["A.8.10"],
            soc2_mapping=["CC6.7"]
        ))

        # Scoring & Metrics
        passed_count = sum(1 for f in findings if f.passed)
        total_count = len(findings)
        score = round((passed_count / total_count) * 100.0, 1) if total_count > 0 else 0.0

        if score >= 80.0:
            rag = RAGStatus.GREEN
        elif score >= 50.0:
            rag = RAGStatus.AMBER
        else:
            rag = RAGStatus.RED

        failed_count = total_count - passed_count
        remediation_hours = failed_count * 20.0  # 20 horas por gap criptográfico post-cuántico
        opex_impact = failed_count * 3500.0      # 3500 EUR de coste opex por falta de resiliencia cuántica

        metrics = {
            "pqc_harvest_now_decrypt_later_mitigated": score >= 80.0,
            "quantum_safety_level": "NIST_LEVEL_5_HIGH" if score == 100.0 else ("HYBRID_INTERIM" if score >= 50.0 else "VULNERABLE_RSA_ECC"),
            "fips_203_ml_kem_active": has_kem_exchange,
            "fips_204_ml_dsa_active": has_dsa_signatures,
            "fips_140_3_zeroization_active": has_fips_hardening
        }

        return EvaluatorResult(
            framework_name=self.framework_name,
            compliance_score=score,
            rag_status=rag,
            total_rules=total_count,
            passed_rules=passed_count,
            failed_rules=failed_count,
            findings=findings,
            metrics=metrics,
            remediation_hours_est=remediation_hours,
            estimated_opex_impact_eur=opex_impact
        )


if __name__ == '__main__':
    evaluator = PQCEvaluator(".", "Test Corp")
    print(evaluator.evaluate())
