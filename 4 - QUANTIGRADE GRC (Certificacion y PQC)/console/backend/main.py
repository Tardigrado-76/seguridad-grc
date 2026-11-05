"""QUANTIGRADE GCR — COCKPIT & CONSOLE FASTAPI ENTRY POINT
Zero-Trust Executive Dashboard & Asynchronous SSE Telemetry Server.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config.clients import CLIENTS_REGISTRY, SCRIPTS_REGISTRY
from .models.schemas import (
    ClientInfo,
    ErrorResponse,
    HealthResponse,
    ScriptInfo,
)
from .routers import audit, compliance, hardening

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("quantigrade_console")

APP_VERSION = os.getenv("APP_VERSION", "3.0.0")
APP_ENV = os.getenv("APP_ENV", "production")
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000",
).split(",")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info(" QUANTIGRADE GCR — Executive Security Console")
    logger.info(" Version: %s | Mode: Zero-Docker Native", APP_VERSION)
    logger.info(" Clients: %d | Scripts: %d", len(CLIENTS_REGISTRY), len(SCRIPTS_REGISTRY))
    logger.info("=" * 60)
    yield
    logger.info("[SHUTDOWN] Quantigrade Console detenido.")


app = FastAPI(
    title="Quantigrade GCR Executive Cockpit",
    description="Panel de control unificado Zero-Trust para orquestación de GCR y telemetría SSE.",
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)


@app.get("/health", response_model=HealthResponse, tags=["Sistema"])
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=APP_VERSION,
        environment=APP_ENV,
        clients_registered=len(CLIENTS_REGISTRY),
        scripts_registered=len(SCRIPTS_REGISTRY),
    )


@app.get("/api/clients", response_model=list[ClientInfo], tags=["Configuración"])
async def list_clients() -> list[ClientInfo]:
    result = []
    for cid, cfg in CLIENTS_REGISTRY.items():
        scripts = []
        for sid, scfg in SCRIPTS_REGISTRY.items():
            if scfg["module"] in cfg["allowed_modules"]:
                scripts.append(
                    ScriptInfo(
                        script_id=sid,
                        module=scfg["module"],
                        label=scfg["label"],
                        description=scfg["description"],
                        interpreter=scfg["interpreter"],
                        requires_admin=scfg["requires_admin"],
                        risk_level=scfg["risk_level"],
                    )
                )
        result.append(
            ClientInfo(
                client_id=cid,
                name=cfg["name"],
                description=cfg["description"],
                allowed_modules=cfg["allowed_modules"],
                available_scripts=scripts,
            )
        )
    return result


app.include_router(audit.router, prefix="/api")
app.include_router(hardening.router, prefix="/api")
app.include_router(compliance.router, prefix="/api")

