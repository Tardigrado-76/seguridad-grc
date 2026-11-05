"""MÓDULO 2 — Remediación y Bastionado (Hardening)
Endpoints para ejecución de ens_fim, disa_stig, harden_vps, kernel_harden y rgpd_purge.
"""

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from ..models.schemas import ExecuteRequest
from ..services.executor import stream_script

router = APIRouter(prefix="/hardening", tags=["Módulo 2 — Hardening"])


@router.post(
    "/run",
    summary="Ejecutar script de bastionado o remediación",
    description="Ejecuta de forma asíncrona un script de remediación y transmite salida vía SSE.",
    response_class=StreamingResponse,
)
async def run_hardening(request: ExecuteRequest) -> StreamingResponse:
    return StreamingResponse(
        stream_script(
            client_id=request.client_id.value,
            script_id=request.script_id.value,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

