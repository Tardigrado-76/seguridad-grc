# scripts/ast_scan.py
# Análisis estático AST para detectar dependencias de terceros en el código fuente.
# Cumplimiento: ENS Alta / NIS2.

import ast
import importlib.util
import os
import sys

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

py_files = []
for root, _dirs, files in os.walk("."):
    # Omitir directorios temporales, de compilación y el venv
    if any(x in root for x in [".venv", "venv", ".git", "dist", "build", ".pytest_cache", ".flake8_cache"]):
        continue
    for file in files:
        if file.endswith(".py"):
            py_files.append(os.path.join(root, file))

imports = set()
for file in py_files:
    try:
        with open(file, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=file)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.add(name.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
    except (OSError, SyntaxError, UnicodeDecodeError):
        pass

# Filtrar librerías estándar y módulos locales del proyecto
stdlib = sys.stdlib_module_names if hasattr(sys, "stdlib_module_names") else set()
local_modules = {"src", "tests"}

missing_packages = []
detected_packages = []

for imp in sorted(imports):
    if imp in stdlib or imp in local_modules or not imp:
        continue

    pip_name = MAPPING.get(imp, imp)
    detected_packages.append(pip_name)

    try:
        spec = importlib.util.find_spec(imp)
    except (ModuleNotFoundError, ValueError, AttributeError):
        spec = None

    if spec is None:
        missing_packages.append(pip_name)

# Devolver los paquetes detectados y los faltantes separados por '|'
