"""orchestrator.py - Central Audit Engine & Execution Orchestrator.
Coordinates evaluators, ISO/SOC2 mapping, document generation, and cryptographic sealing.
"""

import logging
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()  # Zero Trust env loading

logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

from src.evaluators.base import EvaluatorResult
from src.evaluators.cra_sbom import CRASBOMEvaluator
from src.evaluators.data_act import DataActEvaluator
from src.evaluators.dora import DORAEvaluator
from src.evaluators.dsa import DSAEvaluator
from src.evaluators.eidas2 import EIDAS2Evaluator
from src.evaluators.enisa_eucs import ENISAEUCSEvaluator
from src.evaluators.ens_high import ENSHighEvaluator
from src.evaluators.eu_ai_act import EUAIActEvaluator
from src.evaluators.gdpr_toms import GDPRTOMsEvaluator
from src.evaluators.iso27001_soc2_mapper import ISO27001SOC2Mapper
from src.evaluators.nis2 import NIS2Evaluator
from src.reporters.executive_ciso_summary import ExecutiveCISOSummaryReporter
from src.reporters.gdpr_toms_report import GDPRTOMsReporter
from src.reporters.technical_evidence_matrix import TechnicalEvidenceMatrixReporter
from src.sealer.crypto_sealer import CryptoBunkerSealer


class ComplianceOrchestrator:
    def __init__(self, input_path: str, frameworks: list, company_name: str, output_dir: str, report_format: str):
        self.input_path = os.path.abspath(input_path)
        self.frameworks = frameworks
        self.company_name = company_name
        self.report_format = report_format.lower()
        
        # Target destination: <output_path>/<company_name>/
        self.target_output_dir = Path(output_dir) / self.company_name
        self.target_output_dir.mkdir(parents=True, exist_ok=True)

    def run_audit(self) -> dict[str, Any]:
        logger.info("=" * 80)
        logger.info(" IT_COMPLIANCE_MANAGER — AUTOMATED AUDIT & GOVERNANCE ENGINE")
        logger.info("=" * 80)
        logger.info(f" [*] Target Input Path :  {self.input_path}")
        logger.info(f" [*] Organization Name :  {self.company_name}")
        logger.info(f" [*] Target Frameworks :  {', '.join(self.frameworks)}")
        logger.info(f" [*] Output Directory  :  {self.target_output_dir.resolve()}")
        logger.info(f" [*] Report Format     :  {self.report_format.upper()}")
        logger.info("-" * 80)

        evaluator_results: dict[str, EvaluatorResult] = {}

        # 1. Dispatch Framework Evaluators
        if "DORA" in self.frameworks:
            logger.info(" [+] Evaluating DORA (Reglamento UE 2022/2554)...")
            evaluator_results["DORA"] = DORAEvaluator(self.input_path, self.company_name).evaluate()

        if "NIS2" in self.frameworks:
            logger.info(" [+] Evaluating NIS2 (Directiva UE 2022/2555)...")
            evaluator_results["NIS2"] = NIS2Evaluator(self.input_path, self.company_name).evaluate()

        if "ENS_ALTO" in self.frameworks:
            logger.info(" [+] Evaluating ENS Categoría Alta (RD 311/2022)...")
            evaluator_results["ENS_ALTO"] = ENSHighEvaluator(self.input_path, self.company_name).evaluate()

        if "GDPR" in self.frameworks:
            logger.info(" [+] Evaluating RGPD / LOPDGDD (UE 2016/679)...")
            evaluator_results["GDPR"] = GDPRTOMsEvaluator(self.input_path, self.company_name).evaluate()

        if "CRA" in self.frameworks:
            logger.info(" [+] Evaluating CRA & Software Supply Chain (UE 2024/2847)...")
            evaluator_results["CRA"] = CRASBOMEvaluator(self.input_path, self.company_name).evaluate()

        if "EU_AI_ACT" in self.frameworks:
            logger.info(" [+] Evaluating EU AI Act (Reglamento UE 2024/1689)...")
            evaluator_results["EU_AI_ACT"] = EUAIActEvaluator(self.input_path, self.company_name).evaluate()

        if "ENISA_EUCS" in self.frameworks:
            logger.info(" [+] Evaluating ENISA EUCS (EU Cybersecurity Act)...")
            evaluator_results["ENISA_EUCS"] = ENISAEUCSEvaluator(self.input_path, self.company_name).evaluate()

        if "EIDAS_2_0" in self.frameworks or "EIDAS" in self.frameworks:
            logger.info(" [+] Evaluating eIDAS 2.0 (Reglamento UE 2024/1183)...")
            evaluator_results["EIDAS_2_0"] = EIDAS2Evaluator(self.input_path, self.company_name).evaluate()

        if "DATA_ACT" in self.frameworks:
            logger.info(" [+] Evaluating EU Data Act (Reglamento UE 2023/2854)...")
            evaluator_results["DATA_ACT"] = DataActEvaluator(self.input_path, self.company_name).evaluate()

        if "DSA" in self.frameworks:
            logger.info(" [+] Evaluating Digital Services Act (Reglamento UE 2022/2065)...")
            evaluator_results["DSA"] = DSAEvaluator(self.input_path, self.company_name).evaluate()

        # 2. Execute Transversal Gap Closer (ISO 27001 & SOC 2 Mapping)
        logger.info(" [+] Executing ISO 27001:2022 & SOC 2 Cross-Walk Gap Closer...")
        mapper = ISO27001SOC2Mapper(evaluator_results)
        mapper_result = mapper.map_all()

        # 3. Generate Destination Reports & Artifacts
        logger.info(f" [+] Generating compliance documentation in {self.target_output_dir.name}...")
        
        exec_reporter = ExecutiveCISOSummaryReporter(self.company_name, evaluator_results, mapper_result, self.target_output_dir)
        tech_reporter = TechnicalEvidenceMatrixReporter(self.company_name, evaluator_results, self.input_path, self.target_output_dir)
        gdpr_reporter = GDPRTOMsReporter(self.company_name, evaluator_results, self.target_output_dir)

        if self.report_format in ["md", "both"]:
            exec_reporter.generate_markdown()
            tech_reporter.generate_markdown()
            gdpr_reporter.generate_markdown()

        if self.report_format in ["pdf", "both"]:
            exec_reporter.generate_pdf()
            tech_reporter.generate_pdf()
            gdpr_reporter.generate_pdf()

        # 4. Execute Cryptographic Sealer & Merkle Tree Manifest
        logger.info(" [+] Executing Cryptographic Sealer & Merkle Tree Vault...")
        sealer = CryptoBunkerSealer(self.company_name, self.target_output_dir)
        sealer_manifest = sealer.seal_audit_vault()

        logger.info(" [OK] AUDIT AND GOVERNANCE EXECUTION COMPLETED SUCCESSFULLY!")

        return {
            "evaluators": evaluator_results,
            "mapper": mapper_result,
            "manifest": sealer_manifest
        }


if __name__ == '__main__':
    # Production entry point
    pass
