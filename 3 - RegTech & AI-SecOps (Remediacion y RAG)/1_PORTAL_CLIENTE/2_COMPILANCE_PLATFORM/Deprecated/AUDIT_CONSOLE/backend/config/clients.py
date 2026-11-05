"""
Module: clients.py
Description: Production-ready enterprise component for Clients.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


import os
"""
╔══════════════════════════════════════════════════════════════════╗
║              AUDIT_CONSOLE — ZERO-TRUST REGISTRY                ║
║  CLASIFICACIÓN: CONFIDENCIAL — Solo accesible server-side       ║
║  NUNCA exponer este archivo al cliente o incluirlo en builds     ║
╚══════════════════════════════════════════════════════════════════╝

Este módulo implementa el núcleo del modelo Zero-Trust para Audit_Console.

CLIENTS_REGISTRY: Mapeo opaco de IDs lógicos (opacos para el browser) 
a rutas físicas absolutas del servidor. El frontend NUNCA recibe rutas reales.

SCRIPTS_REGISTRY: Catálogo completo de scripts ejecutables con metadatos
de seguridad. Cada script_id apunta a un intérprete y ruta relativa fija.
No se acepta ningún script fuera de este registro.
"""

import sys
from pathlib import Path
from typing import TypedDict

# ──────────────────────────────────────────────────────────────────
# TYPE DEFINITIONS
# ──────────────────────────────────────────────────────────────────

class ClientConfig(TypedDict):
    name: str
    base_path: Path
    description: str
    allowed_modules: list[str]


class ScriptConfig(TypedDict):
    module: str
    relative_path: str
    interpreter: str        # "python" | "powershell" | "bash"
    requires_admin: bool
    description: str
    label: str
    risk_level: str         # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    args: list[str]         # Args fijos adicionales (nunca del usuario)


# ──────────────────────────────────────────────────────────────────
# CLIENTS REGISTRY
# Mapeo: client_id (opaco) → configuración física del servidor
# RESTRICCIÓN: Añadir clientes solo aquí, nunca via API.
# ──────────────────────────────────────────────────────────────────

CLIENTS_REGISTRY: dict[str, ClientConfig] = {
    "tavilga": {
        "name": "Tavilga — Entorno de Producción",
        "base_path": Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS"),
        "description": "Cliente principal. Acceso completo a todos los módulos.",
        "allowed_modules": ["audit", "hardening", "chaos", "compiler", "rag_backup"],
    },
    "bunker_dev": {
        "name": "BunkerOS — Entorno de Desarrollo",
        "base_path": Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS"),
        "description": "Entorno de pruebas. Módulos destructivos deshabilitados.",
        "allowed_modules": ["audit", "chaos", "rag_backup"],
    },
}


# ──────────────────────────────────────────────────────────────────
# SCRIPTS REGISTRY
# Catálogo de scripts ejecutables. WHITELIST ESTRICTA.
# El backend rechaza cualquier script_id fuera de este dict.
# ──────────────────────────────────────────────────────────────────

TOOLS_BASE_PATH = Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/PRODUCTION-READY")

SCRIPTS_REGISTRY: dict[str, ScriptConfig] = {

    # ── MÓDULO 1: Auditor de Cumplimiento ─────────────────────────
    "compliance_audit": {
        "module": "audit",
        "relative_path": r"NORMATIVAS\EU IA Act\ai_compliance_auditor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor IA de Cumplimiento",
        "description": "Análisis AST de código fuente contra ENS Alta, NIS2 y CRA. "
                       "Genera informe de cumplimiento normativo.",
        "risk_level": "LOW",
        "args": [],
    },
    "generate_sbom": {
        "module": "audit",
        "relative_path": r"NORMATIVAS\Supply Chain Security\generate_sbom.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Generador SBOM",
        "description": "Genera Software Bill of Materials (CycloneDX/SPDX) "
                       "e identifica CVEs en dependencias.",
        "risk_level": "LOW",
        "args": ["-i", "."],
    },

    # ── MÓDULO 2: Centro de Hardening ─────────────────────────────
    "bunker_init_alta": {
        "module": "hardening",
        "relative_path": r"NORMATIVAS\IP  PE Hardening\bunker_init_alta.ps1",
        "interpreter": "powershell",
        "requires_admin": True,
        "label": "Hardening ENS Alta",
        "description": "Configuración completa de hardening Windows según "
                       "esquema ENS categoría Alta. Requiere SYSTEM/Admin.",
        "risk_level": "CRITICAL",
        "args": ["-ExecutionPolicy", "Bypass", "-NonInteractive"],
    },
    "disa_stig": {
        "module": "hardening",
        "relative_path": r"NORMATIVAS\ENS 1-3-5\disa_stig_hardening.ps1",
        "interpreter": "powershell",
        "requires_admin": True,
        "label": "DISA STIG Hardening",
        "description": "Aplica controles DISA STIG para Windows Server. "
                       "Requiere privilegios de Administrador.",
        "risk_level": "CRITICAL",
        "args": ["-ExecutionPolicy", "Bypass", "-NonInteractive"],
    },
    "harden_vps": {
        "module": "hardening",
        "relative_path": r"NORMATIVAS\IP  PE Hardening\harden_vps.sh",
        "interpreter": "bash",
        "requires_admin": True,
        "label": "Hardening VPS Linux",
        "description": "Script de bastionado para servidores Linux/Alpine. "
                       "Configura firewall, SSH y auditing. Requiere root.",
        "risk_level": "HIGH",
        "args": [],
    },

    # ── MÓDULO 3: Simulador de Caos e Intrusiones ─────────────────
    "chaos_tests": {
        "module": "chaos",
        "relative_path": r"NORMATIVAS\DORA\15_run_chaos_tests.ps1",
        "interpreter": "powershell",
        "requires_admin": False,
        "label": "Suite de Caos (PowerShell)",
        "description": "Ejecuta batería de tests de resiliencia y chaos engineering "
                       "contra el entorno. Simula fallos de red y servicios.",
        "risk_level": "HIGH",
        "args": ["-ExecutionPolicy", "Bypass"],
    },
    "ddos_simulator": {
        "module": "chaos",
        "relative_path": r"NORMATIVAS\DORA\ddos_simulator.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Simulador DDoS",
        "description": "Herramienta de prueba de carga y simulación de ataques DDoS "
                       "para validar mecanismos de mitigación. Solo entornos de lab.",
        "risk_level": "HIGH",
        "args": [],
    },

    # ── MÓDULO 4: Compilador Inmutable ────────────────────────────
    "build_bunker": {
        "module": "compiler",
        "relative_path": r"NORMATIVAS\build_nuitka.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Build Bunker (Nuitka)",
        "description": "Pipeline de compilación con Nuitka. Genera binario inmutable "
                       "firmado. Incluye ofuscación y strip de símbolos debug.",
        "risk_level": "MEDIUM",
        "args": [],
    },
    "pre_build": {
        "module": "compiler",
        "relative_path": r"NORMATIVAS\Supply Chain Security\pre_build_pipeline.ps1",
        "interpreter": "powershell",
        "requires_admin": False,
        "label": "Pre-Build Pipeline",
        "description": "Pipeline pre-compilación: minificación de assets, "
                       "generación de nonces CSP y verificación de integridad.",
        "risk_level": "LOW",
        "args": ["-ExecutionPolicy", "Bypass"],
    },

    # ── MÓDULO 5: Sincronización RAG y Backups ────────────────────
    "rag_ingestion": {
        "module": "rag_backup",
        "relative_path": r"NORMATIVAS\EU IA Act\rag_ingestion_pipeline.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "RAG Ingestion Pipeline",
        "description": "Indexación y chunking de documentación técnica para el "
                       "pipeline RAG. Genera embeddings y actualiza vector store.",
        "risk_level": "LOW",
        "args": ["-d", "."],
    },
    "secure_backup": {
        "module": "rag_backup",
        "relative_path": r"NORMATIVAS\NIS2\bunker_secure_backup.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Backup Cifrado",
        "description": "Backup cifrado AES-256-GCM con verificación de integridad "
                       "HMAC-SHA256. Soporta destinos locales y remotos.",
        "risk_level": "MEDIUM",
        "args": ["--backup"],
    },
}


# ──────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS (server-side only)
# ──────────────────────────────────────────────────────────────────

def resolve_script_path(client_id: str, script_id: str) -> Path:
    """
    Resuelve la ruta física absoluta de un script de forma segura.
    
    Flujo Zero-Trust (Modo Demo):
    1. Valida script_id contra SCRIPTS_REGISTRY (whitelist)
    2. Construye la ruta con TOOLS_BASE_PATH / relative_path (las herramientas son centrales)
    3. Verifica que el archivo (herramienta) existe en disco
    
    Raises:
        KeyError: script_id desconocido
        FileNotFoundError: script no encontrado en disco
    """
    if script_id not in SCRIPTS_REGISTRY:
        raise KeyError(f"[SECURITY] script_id desconocido: '{script_id}'")

    script = SCRIPTS_REGISTRY[script_id]
    full_path = TOOLS_BASE_PATH / script["relative_path"]

    if not full_path.exists():
        raise FileNotFoundError(
            f"[EXECUTOR] Script (herramienta) no encontrado en disco: {full_path}"
        )

    return full_path


def build_execution_command(script_id: str, script_path: Path) -> list[str]:
    """
    Construye la lista de argumentos completa para subprocess_exec de forma segura:
    - Python: [sys.executable, str(script_path), ...args]
    - PowerShell: ["powershell", "-NoProfile", "-NoLogo", ...args, "-File", str(script_path)]
    - Bash: ["bash", str(script_path), ...args]
    """
    if script_id not in SCRIPTS_REGISTRY:
        raise KeyError(f"[SECURITY] script_id desconocido: '{script_id}'")

    script = SCRIPTS_REGISTRY[script_id]
    interpreter = script["interpreter"]
    script_args = list(script["args"])

    if interpreter == "python":
        py_bin = sys.executable if sys.executable else "python"
        return [py_bin, str(script_path)] + script_args
    elif interpreter == "powershell":
        return ["powershell", "-NoProfile", "-NoLogo"] + script_args + ["-File", str(script_path)]
    elif interpreter == "bash":
        return ["bash", str(script_path)] + script_args
    else:
        return [interpreter, str(script_path)] + script_args


# Compatibilidad hacia atrás
def get_interpreter_cmd(script_id: str) -> list[str]:
    return [SCRIPTS_REGISTRY[script_id]["interpreter"]]




if __name__ == '__main__':
    # Production entry point
    pass
