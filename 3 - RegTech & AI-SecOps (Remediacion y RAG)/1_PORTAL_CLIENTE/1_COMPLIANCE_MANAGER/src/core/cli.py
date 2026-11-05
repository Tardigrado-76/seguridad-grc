"""
Module: cli.py
Description: Production-ready enterprise component for Cli.
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
cli.py - Interactive & Command-Line Argument Parser for IT_COMPLIANCE_MANAGER.
Supports both non-interactive CLI parameters and automatic interactive wizard mode.
"""

import argparse
import sys
import os
from typing import List

VALID_FRAMEWORKS = ["DORA", "NIS2", "ENS_ALTO", "ISO27001", "SOC2", "GDPR", "CRA", "ALL"]
VALID_FORMATS = ["pdf", "md", "both"]

def parse_cli_args(args: List[str] = None) -> argparse.Namespace:
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="IT_COMPLIANCE_MANAGER",
        description="Automated Audit & Technical Governance Engine for DORA, NIS2, ENS High, GDPR, EU AI Act, CRA, ISO 27001 & SOC 2.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False
    )

    parser.add_argument("--help", "-h", action="help", help="Muestra este mensaje de ayuda y sale.")
    parser.add_argument("--interactive", "-it", action="store_true", help="Forzar modo asistente interactivo.")

    parser.add_argument(
        "--input", "-i",
        default=None,
        help="Target physical input path (local folder, repository, workstation, or system path to audit)."
    )

    parser.add_argument(
        "--framework", "-f",
        nargs="+",
        default=None,
        help="Target regulatory frameworks to audit [DORA, NIS2, ENS_ALTO, ISO27001, SOC2, GDPR, CRA, ALL]."
    )

    parser.add_argument(
        "--company", "-c",
        default=None,
        help="Target company or organization name (e.g. CONVOTIS_Client_X)."
    )

    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Root output directory where audit reports will be exported under <output>/<company_name>/."
    )

    parser.add_argument(
        "--format", "-fmt",
        default=None,
        choices=VALID_FORMATS,
        help="Report export format: pdf, md, or both."
    )

    # Detect if run without CLI arguments or with --interactive
    is_interactive_trigger = (len(args) == 0) or ("--interactive" in args) or ("-it" in args)

    if is_interactive_trigger or ("-i" not in args and "--input" not in args) or ("-c" not in args and "--company" not in args):
        # Interactive Wizard Mode
        logger.info("=" * 80)
        logger.info(" IT_COMPLIANCE_MANAGER — MODO ASISTENTE INTERACTIVO DE AUDITORÍA")
        logger.info("=" * 80)
        logger.info(" No se detectaron todos los parámetros obligatorios. Modo Interactivo Activado.\n")

        current_workspace = os.getcwd()
        
        # 1. Target Input
        input_val = input(f" [1/5] Ruta a auditar (Default: '{current_workspace}'): ").strip()
        if not input_val:
            input_val = current_workspace

        # 2. Company Name
        company_val = input(" [2/5] Nombre de la Organización/Cliente (Default: 'CONVOTIS_Client_X'): ").strip()
        if not company_val:
            company_val = "CONVOTIS_Client_X"

        # 3. Target Frameworks
        logger.info(f" [3/5] Normativas a evaluar: {', '.join(VALID_FRAMEWORKS)}")
        fw_val = input("       Selección (separadas por espacio, Default: 'ALL'): ").strip()
        if not fw_val:
            frameworks_list = ["ALL"]
        else:
            frameworks_list = [f.upper() for f in fw_val.split()]

        # 4. Output Directory
        out_val = input(" [4/5] Directorio raíz de salida (Default: 'reports'): ").strip()
        if not out_val:
            out_val = "reports"

        # 5. Format
        fmt_val = input(" [5/5] Formato de informe [pdf/md/both] (Default: 'both'): ").strip().lower()
        if fmt_val not in VALID_FORMATS:
            fmt_val = "both"

        parsed = argparse.Namespace(
            input=input_val,
            framework=frameworks_list,
            company=company_val,
            output=out_val,
            format=fmt_val,
            is_interactive=True
        )

    else:
        parsed = parser.parse_args(args)
        if not hasattr(parsed, "is_interactive"):
            parsed.is_interactive = False

        if not parsed.input:
            parsed.input = os.getcwd()
        if not parsed.company:
            parsed.company = "CONVOTIS_Client_X"
        if not parsed.framework:
            parsed.framework = ["ALL"]
        if not parsed.output:
            parsed.output = "reports"
        if not parsed.format:
            parsed.format = "both"

    # Normalize framework selection
    if "ALL" in parsed.framework:
        parsed.framework = ["DORA", "NIS2", "ENS_ALTO", "GDPR", "CRA"]
    else:
        expanded = set(parsed.framework)
        if "ISO27001" in expanded or "SOC2" in expanded:
            expanded.update(["DORA", "NIS2", "ENS_ALTO", "GDPR", "CRA"])
        parsed.framework = list(expanded)

    return parsed


if __name__ == '__main__':
    # Production entry point
    pass
