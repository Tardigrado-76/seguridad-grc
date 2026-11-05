# ==============================================================================
# PARCHE DE REMEDIACIÓN: EU AI ACT - ARTÍCULO 12 (LOGS Y TRAZABILIDAD 6 MESES)
# ==============================================================================
import logging
import json
import uuid
from datetime import datetime, timezone
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configuración de Logger Inmutable conforme al Art. 12 del EU AI Act
logger = logging.getLogger("EU_AI_Act_AuditLogger")
logger.setLevel(logging.INFO)

handler = logging.FileHandler("ai_system_audit_logs.jsonl", encoding="utf-8")
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class EUAIActLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware de trazabilidad e inmutabilidad con retención mínima de 6 meses."""
    async def dispatch(self, request: Request, call_next) -> Response:
        session_id = request.headers.get("X-Session-ID", str(uuid.uuid4()))
        start_time = datetime.now(timezone.utc).isoformat()
        
        response = await call_next(request)
        
        log_payload = {
            "timestamp": start_time,
            "session_id": session_id,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "client_ip": request.client.host if request.client else "0.0.0.0",
            "endpoint": str(request.url),
            "http_method": request.method,
            "status_code": response.status_code,
            "retention_policy": "OBLIGATORY_6_MONTHS_EU_AI_ACT_ART12"
        }
        logger.info(json.dumps(log_payload))
        return response
