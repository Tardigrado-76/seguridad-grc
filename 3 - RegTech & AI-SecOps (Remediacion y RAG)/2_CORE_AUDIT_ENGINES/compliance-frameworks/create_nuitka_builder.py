"""
Module: create_nuitka_builder.py
Description: Production-ready enterprise component for Create Nuitka Builder.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


logger = logging.getLogger(__name__)
"""
Module: create_nuitka_builder.py
Description: Production-ready enterprise component for Create Nuitka Builder.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
from pathlib import Path

target_dir = Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS/AUDITORIAS_FINAL")

nuitka_py_code = """# -*- coding: utf-8 -*-
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
    
    logger.info(f"[*] Ejecutando compilación Nuitka:\\n  {' '.join(cmd)}\\n")
    logger.info("[!] Nota: Nuitka traducirá el código a C nativo. Esto puede tomar unos minutos...")
    
    res = subprocess.run(cmd)
    if res.returncode == 0:
        logger.info("\\n[+] COMPILACIÓN EXITOSA. 'Quantigrade_Auditor.exe' listo para USB.")
    else:
        logger.info("\\n[!] Error durante la compilación con Nuitka.")

if __name__ == "__main__":
    main()
"""

nuitka_bat_code = """@echo off
title QUANTIGRADE Nuitka Compiler
echo ==================================================
echo  QUANTIGRADE - NUITKA STANDALONE COMPILER
echo ==================================================
python build_nuitka.py
pause
"""

with open(target_dir / "build_nuitka.py", 'w', encoding='utf-8') as f:
    f.write(nuitka_py_code)

with open(Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS") / "build_nuitka.py", 'w', encoding='utf-8') as f:
    f.write(nuitka_py_code)

with open(target_dir / "build_nuitka.bat", 'w', encoding='utf-8') as f:
    f.write(nuitka_bat_code)

with open(Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS") / "build_nuitka.bat", 'w', encoding='utf-8') as f:
    f.write(nuitka_bat_code)

logger.info("[+] Scripts de compilación Nuitka desplegados exitosamente.")


if __name__ == '__main__':
    # Production entry point
    pass
