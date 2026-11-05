"""
MÓDULO 1 — Auditor de Cumplimiento
Scripts: ai_compliance_auditor.py, generate_sbom.py
"""



from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from models.schemas import ExecuteRequest
from services.executor import stream_script

router = APIRouter(prefix="/audit", tags=["Módulo 1 — Auditor de Cumplimiento"])


@router.post(
    "/run",
    summary="Ejecutar script de auditoría de cumplimiento",
    description=(
        "Ejecuta de forma asíncrona un script del Módulo 1 (ai_compliance_auditor.py "
        "o generate_sbom.py) y transmite su salida en tiempo real via SSE."
    ),
    response_class=StreamingResponse,
)
async def run_audit(request: ExecuteRequest) -> StreamingResponse:
    """
    Endpoint SSE para el Módulo 1.
    - Valida client_id y script_id (Enums cerrados, extra=forbid)
    - Resuelve rutas físicas server-side (Zero-Trust)
    - Devuelve StreamingResponse con text/event-stream
    """
    return StreamingResponse(
        stream_script(
            client_id=request.client_id,
            script_id=request.script_id.value,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
            "Connection": "keep-alive",
        },
    )


if __name__ == '__main__':
    # Production entry point
    pass
