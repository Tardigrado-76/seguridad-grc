"""MÓDULO 1 — Auditoría Técnica y Operacional
Endpoints para ejecución de ast_scanner, supply_chain_auditor, iac_drift, rng_entropy y fips_zeroization.
"""

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from ..models.schemas import ExecuteRequest
from ..services.executor import stream_script

router = APIRouter(prefix="/audit", tags=["Módulo 1 — Auditoría"])


@router.post(
    "/run",
    summary="Ejecutar script de auditoría técnica",
    description="Ejecuta de forma asíncrona un script de auditoría y transmite salida vía SSE.",
    response_class=StreamingResponse,
)
async def run_audit(request: ExecuteRequest) -> StreamingResponse:
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

