"""
MÓDULO 3 — Simulador de Caos e Intrusiones
Scripts: run_chaos_tests.ps1, ddos_simulator.py
"""

import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import os

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from models.schemas import ExecuteRequest
from services.executor import stream_script

router = APIRouter(prefix="/chaos", tags=["Módulo 3 — Simulador de Caos"])


@router.post(
    "/run",
    summary="Ejecutar simulador de caos o DDoS",
    description=(
        "⚠ ALTO RIESGO: Ejecuta tests de caos o simulaciones DDoS. "
        "Usar EXCLUSIVAMENTE en entornos de laboratorio aislados. "
        "Transmite logs en tiempo real via SSE."
    ),
    response_class=StreamingResponse,
)
async def run_chaos(request: ExecuteRequest) -> StreamingResponse:
    return StreamingResponse(
        stream_script(
            client_id=request.client_id,
            script_id=request.script_id.value,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


if __name__ == '__main__':
    # Production entry point
    pass
