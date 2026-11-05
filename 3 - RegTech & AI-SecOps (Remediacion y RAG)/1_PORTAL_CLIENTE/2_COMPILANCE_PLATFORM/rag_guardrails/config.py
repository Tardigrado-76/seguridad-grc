#!/usr/bin/env python3
"""
config.py — Configuración Centralizada y Zero Trust para RAG Regulado
======================================================================
Todos los parámetros configurables deben leerse desde variables de entorno
o valores por defecto seguros. Nunca rutas hardcodeadas.

Cumplimiento:
- ENS Categoría Alta (RD 311/2022): Separación de configuración y código.
- DORA Art. 6: Gestión de riesgos TIC — configuración auditada y centralizada.
- CRA (Cyber Resilience Act): Componentes con configuración segura por defecto.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ─── Directorios base ────────────────────────────────────────────────────────
# Directorio del proyecto (donde reside este archivo)
BASE_DIR: Path = Path(__file__).parent.resolve()

# ─── Audit Log (DORA Art. 6 — Trazabilidad de operaciones) ──────────────────
# Variable de entorno: AUDIT_LOG_FILE
# Valor por defecto: dentro del directorio del proyecto (nunca ruta absoluta)
AUDIT_LOG_FILE: str = os.getenv(
    "AUDIT_LOG_FILE",
    str(BASE_DIR / "audit_log.json"),
)
AUDIT_LOG_MAX_ENTRIES: int = int(os.getenv("AUDIT_LOG_MAX_ENTRIES", "200"))

# ─── Uploads temporales (CRA — Protección frente a path traversal) ───────────
UPLOADS_DIR: Path = Path(
    os.getenv("UPLOADS_DIR", str(BASE_DIR / "temp_uploads"))
).resolve()
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# ─── Límites de seguridad (DORA — DoS protection) ────────────────────────────
MAX_FILE_SIZE_MB: float = float(os.getenv("MAX_FILE_SIZE_MB", "10.0"))
MAX_PROMPT_LENGTH: int = int(os.getenv("MAX_PROMPT_LENGTH", "8000"))

# ─── Chunk settings para el pipeline de ingesta ──────────────────────────────
CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "200"))
CHUNK_OVERLAP: int = int(os.getenv("CHUNK_OVERLAP", "30"))

# ─── Embedding provider (offline por defecto — soberanía de datos) ───────────
EMBEDDING_PROVIDER: str = os.getenv("EMBEDDING_PROVIDER", "mock")
OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")
OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")

# ─── Guardarraíles activos por defecto (ENS Alta — Principio de mínimo privilegio) ─
GUARDRAILS_DEFAULT_ACTIVE: bool = os.getenv("GUARDRAILS_DEFAULT_ACTIVE", "true").lower() == "true"
