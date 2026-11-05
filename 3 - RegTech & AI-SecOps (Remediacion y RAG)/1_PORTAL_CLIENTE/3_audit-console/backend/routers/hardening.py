"""
MÓDULO 2 — Centro de Hardening
Scripts: bunker_init_alta.ps1, disa_stig_hardening.ps1, harden_vps.sh
"""



from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from models.schemas import ExecuteRequest
from services.executor import stream_script

router = APIRouter(prefix="/hardening", tags=["Módulo 2 — Centro de Hardening"])


@router.post(
    "/run",
    summary="Ejecutar script de hardening del sistema",
    description=(
        "⚠ ALTO RIESGO: Ejecuta scripts de hardening (ENS Alta, DISA STIG, VPS). "
        "Requiere privilegios de Administrador/root en el servidor. "
        "Transmite logs en tiempo real via SSE."
    ),
    response_class=StreamingResponse,
)
async def run_hardening(request: ExecuteRequest) -> StreamingResponse:
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
