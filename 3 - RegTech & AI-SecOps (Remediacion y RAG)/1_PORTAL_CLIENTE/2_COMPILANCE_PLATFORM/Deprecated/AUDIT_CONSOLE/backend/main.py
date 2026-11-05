"""
╔══════════════════════════════════════════════════════════════════╗
║              AUDIT_CONSOLE — FastAPI Entry Point                ║
║  BunkerOS Security Dashboard Backend                            ║
║  v1.0.0 — Zero-Trust Architecture                              ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


import asyncio
import logging
import os
import sys

# ── FIX WINDOWS: asyncio subprocess ─────────────────────────────────────
# Python 3.12+ on Windows usa SelectorEventLoop por defecto, que NO
# soporta asyncio.create_subprocess_exec. Debemos forzar Proactor.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
# ──────────────────────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.clients import CLIENTS_REGISTRY, SCRIPTS_REGISTRY
from models.schemas import HealthResponse, ErrorResponse
from routers import audit, hardening, chaos, compiler, rag_backup

# ──────────────────────────────────────────────────────────────────
# BOOTSTRAP
# ──────────────────────────────────────────────────────────────────

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("audit_console")

APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
APP_ENV     = os.getenv("APP_ENV", "development")

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")


# ──────────────────────────────────────────────────────────────────
# LIFESPAN
# ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info(" AUDIT_CONSOLE — BunkerOS Security Dashboard")
    logger.info(" Version : %s | Env: %s", APP_VERSION, APP_ENV)
    logger.info(" Clientes cargados : %d", len(CLIENTS_REGISTRY))
    logger.info(" Scripts cargados  : %d", len(SCRIPTS_REGISTRY))
    logger.info(" CORS permitido    : %s", ALLOWED_ORIGINS)
    logger.info("=" * 60)
    yield
    logger.info("[SHUTDOWN] Audit_Console detenido.")


# ──────────────────────────────────────────────────────────────────
# APP INSTANCE
# ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Audit_Console — BunkerOS Security Dashboard",
    description=(
        "Panel de control unificado Zero-Trust para gestión centralizada "
        "de scripts de seguridad DevSecOps. "
        "Transmisión asíncrona de logs via Server-Sent Events (SSE)."
    ),
    version=APP_VERSION,
    docs_url="/api/docs" if APP_ENV == "development" else None,
    redoc_url="/api/redoc" if APP_ENV == "development" else None,
    openapi_url="/api/openapi.json" if APP_ENV == "development" else None,
    lifespan=lifespan,
)


# ──────────────────────────────────────────────────────────────────
# MIDDLEWARES
# ──────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; require-trusted-types-for 'script';"
    )
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response



# ──────────────────────────────────────────────────────────────────
# EXCEPTION HANDLERS
# ──────────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("[UNHANDLED] %s %s → %s", request.method, request.url, exc)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal Server Error",
            detail="Error interno del servidor. Consulta los logs del backend.",
            code=500,
        ).model_dump(),
    )


# ──────────────────────────────────────────────────────────────────
# ROUTERS — prefijo base /api/v1
# ──────────────────────────────────────────────────────────────────

API_PREFIX = "/api/v1"

app.include_router(audit.router,      prefix=API_PREFIX)
app.include_router(hardening.router,  prefix=API_PREFIX)
app.include_router(chaos.router,      prefix=API_PREFIX)
app.include_router(compiler.router,   prefix=API_PREFIX)
app.include_router(rag_backup.router, prefix=API_PREFIX)


# ──────────────────────────────────────────────────────────────────
# UTILITY ENDPOINTS
# ──────────────────────────────────────────────────────────────────

@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["Sistema"],
    summary="Health check del servidor",
)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=APP_VERSION,
        clients_loaded=len(CLIENTS_REGISTRY),
        scripts_loaded=len(SCRIPTS_REGISTRY),
    )


@app.get(
    "/api/v1/catalog",
    tags=["Sistema"],
    summary="Catálogo de clientes y scripts disponibles",
    description="Devuelve el catálogo de clientes y scripts SIN exponer rutas físicas.",
)
async def get_catalog():
    """
    Endpoint de catálogo seguro.
    Expone nombres y metadatos públicos — NUNCA rutas físicas.
    """
    clients = [
        {
            "client_id": cid,
            "name": cfg["name"],
            "description": cfg["description"],
            "allowed_modules": cfg["allowed_modules"],
        }
        for cid, cfg in CLIENTS_REGISTRY.items()
    ]

    scripts = [
        {
            "script_id": sid,
            "label": scfg["label"],
            "description": scfg["description"],
            "module": scfg["module"],
            "interpreter": scfg["interpreter"],
            "requires_admin": scfg["requires_admin"],
            "risk_level": scfg["risk_level"],
        }
        for sid, scfg in SCRIPTS_REGISTRY.items()
    ]

    return {"clients": clients, "scripts": scripts}


# ──────────────────────────────────────────────────────────────────
# ENTRYPOINT (desarrollo)
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
