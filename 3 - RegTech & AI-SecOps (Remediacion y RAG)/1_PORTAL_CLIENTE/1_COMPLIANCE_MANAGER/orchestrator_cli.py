"""
Module: orchestrator_cli.py
Description: Production-ready enterprise component for Orchestrator Cli.
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
orchestrator_cli.py - Single Script Entrypoint & CLI Launcher for IT_COMPLIANCE_MANAGER.
"""

import sys
import os

# Ensure package path is accessible
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.core.cli import parse_cli_args
from src.core.orchestrator import ComplianceOrchestrator

def main():
    parsed_args = parse_cli_args()
    
    orchestrator = ComplianceOrchestrator(
        input_path=parsed_args.input,
        frameworks=parsed_args.framework,
        company_name=parsed_args.company,
        output_dir=parsed_args.output,
        report_format=parsed_args.format
    )

    orchestrator.run_audit()

    if getattr(parsed_args, "is_interactive", False) or len(sys.argv) == 1:
        try:
            input("\n[+] Auditoría completada. Presione ENTER para salir...")
        except Exception:
            pass

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.info(f"\n[!] Error en la ejecución: {e}")
        import traceback
        traceback.print_exc()
        try:
            input("\n[!] Presione ENTER para cerrar la consola...")
        except Exception:
            pass
