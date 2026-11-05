"""
MÓDULO 5 — Sincronización RAG y Backups
Scripts: rag_ingestion_pipeline.py, bunker_secure_backup.py
"""



from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from models.schemas import ExecuteRequest
from services.executor import stream_script

router = APIRouter(prefix="/rag-backup", tags=["Módulo 5 — RAG & Backups"])


@router.post(
    "/run",
    summary="Ejecutar pipeline RAG o backup cifrado",
    description=(
        "Ejecuta el pipeline de ingestión RAG (rag_ingestion_pipeline.py) "
        "o el sistema de backup cifrado AES-256 (bunker_secure_backup.py). "
        "Transmite logs en tiempo real via SSE."
    ),
    response_class=StreamingResponse,
)
async def run_rag_backup(request: ExecuteRequest) -> StreamingResponse:
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
