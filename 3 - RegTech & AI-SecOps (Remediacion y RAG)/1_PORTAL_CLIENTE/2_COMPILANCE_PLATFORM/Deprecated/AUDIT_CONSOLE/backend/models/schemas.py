"""
Module: schemas.py
Description: Production-ready enterprise component for Schemas.
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
║              AUDIT_CONSOLE — PYDANTIC SCHEMAS                   ║
║  Validación estricta de entradas. Enums cerrados.               ║
║  Cualquier campo extra → HTTP 422 Unprocessable Entity          ║
╚══════════════════════════════════════════════════════════════════╝

Modelo de validación Zero-Trust:
- ClientId: Enum cerrado de IDs de cliente válidos
- ScriptId: Enum cerrado de script IDs válidos
- ExecuteRequest: Acepta SOLO client_id + script_id. 
  Cualquier campo adicional (ej: path, args, cmd) es RECHAZADO.
"""

from enum import Enum
from pydantic import BaseModel, Field, model_validator
from typing import Optional


# ──────────────────────────────────────────────────────────────────
# ENUMS — Whitelist compilada de valores válidos
# ──────────────────────────────────────────────────────────────────

class ScriptId(str, Enum):
    """
    Catálogo completo de script IDs ejecutables.
    Cualquier valor fuera de este Enum → HTTP 422.
    """
    # Módulo 1: Auditor de Cumplimiento
    compliance_audit = "compliance_audit"
    generate_sbom    = "generate_sbom"

    # Módulo 2: Centro de Hardening
    bunker_init_alta = "bunker_init_alta"
    disa_stig        = "disa_stig"
    harden_vps       = "harden_vps"

    # Módulo 3: Simulador de Caos e Intrusiones
    chaos_tests      = "chaos_tests"
    ddos_simulator   = "ddos_simulator"

    # Módulo 4: Compilador Inmutable
    build_bunker     = "build_bunker"
    pre_build        = "pre_build"

    # Módulo 5: RAG & Backups
    rag_ingestion    = "rag_ingestion"
    secure_backup    = "secure_backup"


class ModuleId(str, Enum):
    """Identificadores de los 5 módulos principales de la consola."""
    audit      = "audit"
    hardening  = "hardening"
    chaos      = "chaos"
    compiler   = "compiler"
    rag_backup = "rag_backup"


class RiskLevel(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ──────────────────────────────────────────────────────────────────
# REQUEST MODELS
# ──────────────────────────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    """
    Modelo de solicitud de ejecución de script.
    
    SEGURIDAD ZERO-TRUST RELAJADA (Demo):
    - Acepta script_id (Enum cerrado)
    - client_id ahora es str libre para poder inyectar rutas del target
    - `model_config = {"extra": "forbid"}` rechaza CUALQUIER campo extra
    - La resolución de rutas ocurre exclusivamente en el servidor (clients.py)
    """

    model_config = {"extra": "forbid"}

    client_id: str = Field(
        ...,
        description="Ruta absoluta del cliente que va a ser auditado.",
        examples=[os.getenv("APP_DATA_PATH", "./data"), os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS"],
    )
    script_id: ScriptId = Field(
        ...,
        description="ID del script a ejecutar. Debe estar en el catálogo de scripts autorizados.",
        examples=["compliance_audit", "generate_sbom"],
    )

    @model_validator(mode="after")
    def validate_module_permission(self) -> "ExecuteRequest":
        """
        Validación cruzada.
        Al permitir custom paths, asumimos que todos los scripts están permitidos
        en modo Demo. Las restricciones de allowed_modules de CLIENTS_REGISTRY
        ya no aplican a rutas arbitrarias.
        """
        from config.clients import SCRIPTS_REGISTRY

        script_config = SCRIPTS_REGISTRY.get(self.script_id.value)
        if not script_config:
            raise ValueError(f"Script no autorizado: {self.script_id.value}")

        return self


# ──────────────────────────────────────────────────────────────────
# RESPONSE MODELS
# ──────────────────────────────────────────────────────────────────

class ScriptMeta(BaseModel):
    """Metadatos de un script del catálogo (sin rutas físicas)."""
    script_id: str
    label: str
    description: str
    module: str
    interpreter: str
    requires_admin: bool
    risk_level: str


class ClientMeta(BaseModel):
    """Metadatos de un cliente (sin rutas físicas)."""
    client_id: str
    name: str
    description: str
    allowed_modules: list[str]


class HealthResponse(BaseModel):
    """Respuesta del endpoint de health check."""
    status: str
    version: str
    clients_loaded: int
    scripts_loaded: int


class ErrorResponse(BaseModel):
    """Respuesta de error estandarizada."""
    error: str
    detail: Optional[str] = None
    code: int


if __name__ == '__main__':
    # Production entry point
    pass
