"""
Module: setup_git_hooks.py
Description: Production-ready enterprise component for Setup Git Hooks.
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
setup_git_hooks.py — Automatización de Configuración de Git Hooks (ENS/CRA)
==========================================================================
Cumplimiento: CRA (Cyber Resilience Act) - Aseguramiento de Cadena de Suministro.
Fuerza la instalación local del framework de pre-commit y el hook de Gitleaks.
"""

import os
import sys
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

try:
    from src.bunker_logger import log_auditoria
except ImportError:
    def log_auditoria(user, action, message):
        logger.info(f"[AUDIT] [{user}] [{action}] {message}")


def run_command(cmd, desc=""):
    logger.info(f"[*] Ejecutando: {' '.join(cmd)} ({desc})")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=PROJECT_ROOT)
        logger.info(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        logger.info(f"[!] Error al ejecutar comando: {e}")
        logger.info(e.stderr)
        return False
    except FileNotFoundError:
        logger.info(f"[!] Comando no encontrado: {cmd[0]}")
        return False


def main():
    logger.info("\n[*] BunkerOS — Configuración Obligatoria de Git Hooks de Seguridad (Option B)")
    
    # 1. Verificar si git está inicializado
    git_dir = os.path.join(PROJECT_ROOT, ".git")
    if not os.path.exists(git_dir):
        logger.info("[!] Error: No se encontró el directorio .git. ¿Este es un repositorio Git?")
        sys.exit(1)

    # 2. Intentar instalar 'pre-commit' usando pip (si no está disponible)
    try:
        import pre_commit
        logger.info("[+] pre-commit ya está instalado en el entorno Python.")
    except ImportError:
        logger.info("[*] pre-commit no encontrado en el entorno local. Instalando vía pip...")
        # Usamos sys.executable para garantizar que se instala en el mismo python virtualenv activo
        pip_installed = run_command([sys.executable, "-m", "pip", "install", "pre-commit"], "Instalación de pre-commit")
        if not pip_installed:
            logger.info("[!] Error: No se pudo instalar 'pre-commit' usando pip.")
            sys.exit(1)

    # 3. Registrar el hook de git
    # Ejecutar 'pre-commit install'
    # Buscamos el ejecutable de pre-commit en el entorno virtual
    precommit_bin = "pre-commit"
    # En Windows virtualenv, suele estar en Scripts/pre-commit.exe
    # En Unix, en bin/pre-commit
    venv_bin_dir = "Scripts" if os.name == "nt" else "bin"
    venv_precommit = os.path.join(sys.prefix, venv_bin_dir, "pre-commit")
    if os.name == "nt":
        venv_precommit += ".exe"

    if os.path.exists(venv_precommit):
        precommit_bin = venv_precommit

    success = run_command([precommit_bin, "install"], "Registro de Git pre-commit hooks")
    
    if success:
        logger.info("[+] Git Hooks registrados con éxito localmente.")
        log_auditoria("SYSTEM", "GIT_HOOKS_INSTALLED", "Git pre-commit hooks configurados con éxito en la máquina local del desarrollador.")
    else:
        logger.info("[!] Error al registrar los Git Hooks. Asegúrate de tener pre-commit instalado en el path.")
        sys.exit(1)


if __name__ == "__main__":
    main()
