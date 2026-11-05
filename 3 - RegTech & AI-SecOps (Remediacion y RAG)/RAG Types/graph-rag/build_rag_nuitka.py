"""Module: build_rag_nuitka.py
Description: Production-ready enterprise component for Build Rag Nuitka.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import logging
import os

from dotenv import load_dotenv

load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv

load_dotenv()  # Zero Trust local environment loader


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# -*- coding: utf-8 -*-
"""
Script de compilación Nuitka para RAG Assistant Suite
=====================================================
Compila `rag_assistant_gui.py` a ejecutable nativo en C (`RAG_Assistant_Suite.exe`).
"""

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    logger.info("==================================================")
    logger.info(" COMPILADOR NUITKA - RAG ASSISTANT SUITE (.EXE)")
    logger.info("==================================================")

    try:
        import nuitka
        logger.info("[+] Nuitka disponible.")
    except ImportError:
        logger.info("[*] Instalando Nuitka...")
        subprocess.run([sys.executable, "-m", "pip", "install", "nuitka"], check=True)

    script = Path(__file__).parent / "rag_assistant_gui.py"

    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--onefile",
        "--enable-plugin=tk-inter",
        "--module-parameter=torch-disable-jit=yes",
        "--follow-imports",
        "--assume-yes-for-downloads",
        "--windows-icon-from-ico=logo.ico",
        "--output-filename=RAG_Assistant_Suite.exe",
        str(script),
    ]

    logger.info(f"[*] Compilando ejecutable nativo en C:\n  {' '.join(cmd)}\n")
    res = subprocess.run(cmd)

    if res.returncode == 0:
        logger.info("\n[+] COMPILACIÓN EXITOSA. 'RAG_Assistant_Suite.exe' generado y listo para usar.")
    else:
        logger.info("\n[!] Fallo durante la compilación Nuitka.")

if __name__ == "__main__":
    main()
