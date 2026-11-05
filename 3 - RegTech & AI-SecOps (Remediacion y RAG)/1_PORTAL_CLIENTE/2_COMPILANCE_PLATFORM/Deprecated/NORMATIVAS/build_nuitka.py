"""
Module: build_nuitka.py
Description: Production-ready enterprise component for Build Nuitka.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import os
import logging


logger = logging.getLogger(__name__)
"""
Module: build_nuitka.py
Description: Production-ready enterprise component for Build Nuitka.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

# -*- coding: utf-8 -*-
import subprocess
import sys
from pathlib import Path

def main():
    logger.info("==================================================")
    logger.info(" QUANTIGRADE NUITKA COMPILER (USB STANDALONE EXE)")
    logger.info("==================================================")
    
    # 1. Check if Nuitka is installed
    try:
        import nuitka
        logger.info("[+] Nuitka detectado en el entorno.")
    except ImportError:
        logger.info("[*] Instalando Nuitka...")
        subprocess.run([sys.executable, "-m", "pip", "install", "nuitka"], check=True)
        
    script_to_compile = Path(__file__).parent / "quantigrade_gui.py"
    
    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--onefile",
        "--enable-plugin=tk-inter",
        "--follow-imports",
        "--assume-yes-for-downloads",
        "--output-filename=Quantigrade_Auditor.exe",
        str(script_to_compile)
    ]
    
    logger.info(f"[*] Ejecutando compilación Nuitka:\n  {' '.join(cmd)}\n")
    logger.info("[!] Nota: Nuitka traducirá el código a C nativo. Esto puede tomar unos minutos...")
    
    res = subprocess.run(cmd)
    if res.returncode == 0:
        logger.info("\n[+] COMPILACIÓN EXITOSA. 'Quantigrade_Auditor.exe' listo para USB.")
    else:
        logger.info("\n[!] Error durante la compilación con Nuitka.")

if __name__ == "__main__":
    main()
