"""
MÓDULO 4 — Compilador Inmutable
Scripts: build_bunker.ps1, pre_build_pipeline.ps1
"""



from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from models.schemas import ExecuteRequest
from services.executor import stream_script

router = APIRouter(prefix="/compiler", tags=["Módulo 4 — Compilador Inmutable"])


@router.post(
    "/run",
    summary="Ejecutar pipeline de compilación",
    description=(
        "Ejecuta el pipeline de compilación con Nuitka (build_bunker.ps1) "
        "o el pipeline pre-build de assets/CSP. "
        "Transmite logs en tiempo real via SSE."
    ),
    response_class=StreamingResponse,
)
async def run_compiler(request: ExecuteRequest) -> StreamingResponse:
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
