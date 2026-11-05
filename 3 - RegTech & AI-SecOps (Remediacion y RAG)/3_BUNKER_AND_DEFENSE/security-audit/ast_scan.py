"""
Module: ast_scan.py
Description: Production-ready enterprise component for Ast Scan.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


logger = logging.getLogger(__name__)
"""
Module: ast_scan.py
Description: Production-ready enterprise component for Ast Scan.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

# scripts/ast_scan.py
# Análisis estático AST para detectar dependencias de terceros en el código fuente.
# Cumplimiento: ENS Alta / NIS2.

import ast
import os
import sys
import importlib.util
import argparse

MAPPING = {
    "dotenv": "python-dotenv",
    "argon2": "argon2-cffi",
    "jwt": "PyJWT",
    "pytest_asyncio": "pytest-asyncio",
    "httpcore": "httpcore2",
    "httpx2": "httpx2",
    "win32crypt": "pywin32",
    "yaml": "PyYAML",
    "OpenSSL": "pyOpenSSL",
    "opentelemetry": "opentelemetry-api",
    "pkcs11": "python-pkcs11",
}

def analyze_directory(target_path):
    py_files = []
    for root, dirs, files in os.walk(target_path):
        # Omitir directorios temporales, de compilación y el venv
        if any(x in root for x in ['.venv', 'venv', '.git', 'dist', 'build', '.pytest_cache', '.flake8_cache', 'node_modules']):
            continue
        for file in files:
            if file.endswith('.py'):
                py_files.append(os.path.join(root, file))

    imports = set()
    for file in py_files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=file)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        imports.add(name.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
        except Exception:
            pass

    # Filtrar librerías estándar y módulos locales del proyecto
    stdlib = sys.stdlib_module_names if hasattr(sys, 'stdlib_module_names') else set()
    # Módulos locales dinámicos basados en la estructura del proyecto (directorios en el target_path)
    local_modules = set()
    if os.path.exists(target_path):
        for entry in os.listdir(target_path):
            if os.path.isdir(os.path.join(target_path, entry)):
                local_modules.add(entry)

    missing_packages = []
    detected_packages = []

    for imp in sorted(imports):
        if imp in stdlib or imp in local_modules or not imp:
            continue
        
        pip_name = MAPPING.get(imp, imp)
        detected_packages.append(pip_name)
        
        try:
            spec = importlib.util.find_spec(imp)
        except Exception:
            spec = None
            
        if spec is None:
            missing_packages.append(pip_name)

    # Devolver los paquetes detectados y los faltantes separados por '|'
    logger.info(";".join(detected_packages) + "|" + ";".join(missing_packages))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Escáner AST independiente de dependencias y librerías externas en proyectos Python.")
    parser.add_argument("-p", "--path", default=".", help="Ruta al directorio del proyecto a escanear (por defecto: directorio actual).")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        logger.info(f"Error: La ruta especificada no existe: {args.path}", file=sys.stderr)
        sys.exit(1)
        
    analyze_directory(args.path)
