"""MÓDULO 3 — Cumplimiento Normativo Activo (DORA / NIS2 / RGPD)
Endpoints para ejecución de clasificadores, drill de failover, reportes ANC y brechas.
"""

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from ..models.schemas import ExecuteRequest
from ..services.executor import stream_script

router = APIRouter(prefix="/compliance", tags=["Módulo 3 — Cumplimiento"])


@router.post(
    "/run",
    summary="Ejecutar script de cumplimiento normativo",
    description="Ejecuta de forma asíncrona un script normativo y transmite salida vía SSE.",
    response_class=StreamingResponse,
)
async def run_compliance(request: ExecuteRequest) -> StreamingResponse:
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

