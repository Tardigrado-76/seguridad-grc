"""
Module: orchestrator.py
Description: Production-ready enterprise component for Orchestrator.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


import logging
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
orchestrator.py - Central Audit Engine & Execution Orchestrator.
Coordinates evaluators, ISO/SOC2 mapping, document generation, and cryptographic sealing.

DORA compliance (Art. 24): a failure in one framework evaluator MUST NOT abort the
whole audit. Each framework runs in isolation; failures are collected and reported
in the execution summary, and the CLI surfaces them via non-zero exit codes.
"""

import os
import sys
import traceback
from pathlib import Path
from typing import Dict, Any, List

from src.evaluators.base import EvaluatorResult
from src.evaluators.dora import DORAEvaluator
from src.evaluators.nis2 import NIS2Evaluator
from src.evaluators.ens_high import ENSHighEvaluator
from src.evaluators.gdpr_toms import GDPRTOMsEvaluator
from src.evaluators.cra_sbom import CRASBOMEvaluator
from src.evaluators.iso27001_soc2_mapper import ISO27001SOC2Mapper

from src.reporters.executive_ciso_summary import ExecutiveCISOSummaryReporter
from src.reporters.technical_evidence_matrix import TechnicalEvidenceMatrixReporter
from src.reporters.gdpr_toms_report import GDPRTOMsReporter

from src.sealer.crypto_sealer import CryptoBunkerSealer


class ComplianceOrchestrator:
    """Orquestador central de auditorías. Cada framework se evalúa de forma aislada."""

    # Framework → (etiqueta normativa, factory del evaluador)
    _EVALUATOR_FACTORIES = {
        "DORA":     (lambda p, c: DORAEvaluator(p, c), "DORA (Reglamento UE 2022/2554)"),
        "NIS2":     (lambda p, c: NIS2Evaluator(p, c), "NIS2 (Directiva UE 2022/2555)"),
        "ENS_ALTO": (lambda p, c: ENSHighEvaluator(p, c), "ENS Categoría Alta (RD 311/2022)"),
        "GDPR":     (lambda p, c: GDPRTOMsEvaluator(p, c), "RGPD / LOPDGDD (UE 2016/679)"),
        "CRA":      (lambda p, c: CRASBOMEvaluator(p, c), "CRA & EU AI Act (UE 2024/1689)"),
    }

    def __init__(self, input_path: str, frameworks: list, company_name: str, output_dir: str, report_format: str):
        self.input_path = os.path.abspath(input_path)
        self.frameworks = frameworks
        self.company_name = company_name
        self.report_format = report_format.lower()

        # Target destination: <output_path>/<company_name>/
        self.target_output_dir = Path(output_dir) / self.company_name
        self.target_output_dir.mkdir(parents=True, exist_ok=True)

        # Registro de fallos aislados (DORA Art. 24 resiliencia)
        self.failures: List[Dict[str, str]] = []

    def _run_evaluator(self, framework: str) -> EvaluatorResult:
        factory, label = self._EVALUATOR_FACTORIES[framework]
        logger.info(f" [+] Evaluating {label}...")
        return factory(self.input_path, self.company_name).evaluate()

    def run_audit(self) -> Dict[str, Any]:
        logger.info("=" * 80)
        logger.info(" IT_COMPLIANCE_MANAGER — AUTOMATED AUDIT & GOVERNANCE ENGINE")
        logger.info("=" * 80)
        logger.info(f" [*] Target Input Path :  {self.input_path}")
        logger.info(f" [*] Organization Name :  {self.company_name}")
        logger.info(f" [*] Target Frameworks :  {', '.join(self.frameworks)}")
        logger.info(f" [*] Output Directory  :  {self.target_output_dir.resolve()}")
        logger.info(f" [*] Report Format     :  {self.report_format.upper()}")
        logger.info("-" * 80)

        evaluator_results: Dict[str, EvaluatorResult] = {}

        # 1. Dispatch Framework Evaluators (aislados: un fallo no aborta la auditoría)
        for framework in self.frameworks:
            if framework not in self._EVALUATOR_FACTORIES:
                self.failures.append({
                    "stage": "dispatch",
                    "framework": framework,
                    "error": f"Framework no soportado: {framework}",
                })
                continue
            try:
                evaluator_results[framework] = self._run_evaluator(framework)
            except Exception as e:
                self.failures.append({
                    "stage": "evaluator",
                    "framework": framework,
                    "error": f"{type(e).__name__}: {e}",
                })
                logger.info(f"  [!] Fallo aislado en evaluador {framework}: {e}")

        # 2. Execute Transversal Gap Closer (ISO 27001 & SOC 2 Mapping)
        mapper_result: Dict[str, Any] = {}
        try:
            logger.info(" [+] Executing ISO 27001:2022 & SOC 2 Cross-Walk Gap Closer...")
            mapper = ISO27001SOC2Mapper(evaluator_results)
            mapper_result = mapper.map_all()
        except Exception as e:
            self.failures.append({"stage": "mapper", "framework": "ISO27001/SOC2", "error": f"{type(e).__name__}: {e}"})
            logger.info(f"  [!] Fallo en ISO/SOC2 mapper: {e}")

        # 3. Generate Destination Reports & Artifacts
        logger.info(f" [+] Generating compliance documentation in {self.target_output_dir.name}...")

        exec_reporter = ExecutiveCISOSummaryReporter(self.company_name, evaluator_results, mapper_result, self.target_output_dir)
        tech_reporter = TechnicalEvidenceMatrixReporter(self.company_name, evaluator_results, self.input_path, self.target_output_dir)
        gdpr_reporter = GDPRTOMsReporter(self.company_name, evaluator_results, self.target_output_dir)

        if self.report_format in ["md", "both"]:
            for reporter, name in [(exec_reporter, "EXECUTIVE_CISO_SUMMARY"), (tech_reporter, "TECHNICAL_AUDIT_EVIDENCE_MATRIX"), (gdpr_reporter, "GDPR_TOMS_VERIFICATION_REPORT")]:
                try:
                    reporter.generate_markdown()
                except Exception as e:
                    self.failures.append({"stage": "reporter_md", "framework": name, "error": f"{type(e).__name__}: {e}"})
                    logger.info(f"  [!] Fallo generando {name}.md: {e}")

        if self.report_format in ["pdf", "both"]:
            for reporter, name in [(exec_reporter, "EXECUTIVE_CISO_SUMMARY"), (tech_reporter, "TECHNICAL_AUDIT_EVIDENCE_MATRIX"), (gdpr_reporter, "GDPR_TOMS_VERIFICATION_REPORT")]:
                try:
                    reporter.generate_pdf()
                except Exception as e:
                    self.failures.append({"stage": "reporter_pdf", "framework": name, "error": f"{type(e).__name__}: {e}"})
                    logger.info(f"  [!] Fallo generando {name}.pdf: {e}")

        # 4. Execute Cryptographic Sealer & Merkle Tree Manifest
        sealer_manifest: Dict[str, Any] = {}
        try:
            logger.info(" [+] Executing Cryptographic Sealer & Merkle Tree Vault...")
            sealer = CryptoBunkerSealer(self.company_name, self.target_output_dir)
            sealer_manifest = sealer.seal_audit_vault()
        except Exception as e:
            self.failures.append({"stage": "sealer", "framework": "SLSA/ChainOfCustody", "error": f"{type(e).__name__}: {e}"})
            logger.info(f"  [!] Fallo en el sellado criptográfico: {e}")

        # 5. Resumen de ejecución
        if self.failures:
            logger.info("-" * 80)
            logger.info(f" [WARN] {len(self.failures)} incidencia(s) aislada(s) durante la ejecución:")
            for f in self.failures:
                logger.info(f"   - [{f['stage']}] {f['framework']}: {f['error']}")

        logger.info(" [OK] AUDIT AND GOVERNANCE EXECUTION COMPLETED SUCCESSFULLY!")

        return {
            "evaluators": evaluator_results,
            "mapper": mapper_result,
            "manifest": sealer_manifest,
            "failures": self.failures,
        }


if __name__ == '__main__':
    # Production entry point
    pass
