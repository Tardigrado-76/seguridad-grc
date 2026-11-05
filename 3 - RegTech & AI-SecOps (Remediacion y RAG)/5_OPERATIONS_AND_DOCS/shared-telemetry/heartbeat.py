"""BunkerOS Node — Heartbeat Endpoint (Fase 2.1)
Normativa: ENS Categoría Alta, NIS2, CWE-20
Emite telemetría criptográfica del nodo hacia el HQ (Nest.js BFF).
"""

import hashlib
import hmac
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/node", tags=["heartbeat"])

# Secret pre-compartido (en producción: derivado del TPM via DPAPI/ECDH)
raw_hq_secret = os.environ["HQ_HMAC_SECRET"]
if not raw_hq_secret:
    msg = "HQ_HMAC_SECRET no definido"
    raise ValueError(msg)
HQ_SECRET = bytearray(raw_hq_secret.encode())
raw_hq_secret = "" # nosec B105
os.environ.pop("HQ_HMAC_SECRET", None)


class HeartbeatPayload(BaseModel):
    node_id: str = Field(..., min_length=3, max_length=16, pattern=r"^[A-Z0-9\-]+$")
    engine_version: str = Field(..., max_length=32)
    tpm_integrity: str = Field(..., pattern=r"^(Valid|Compromised|Unknown)$")
    timestamp_utc: str  # ISO 8601


class HeartbeatResponse(BaseModel):
    status: str
    server_ts: str
    ack_hash: str


def _compute_hmac(payload: str) -> str:
    """Calcula HMAC-SHA256 del payload para autenticidad del heartbeat."""
    return hmac.new(HQ_SECRET, payload.encode(), hashlib.sha256).hexdigest()


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def node_heartbeat(
    payload: HeartbeatPayload,
    request: Request,
):
    """Endpoint de Heartbeat para nodos de la flota.
    Recibe estado criptográfico del nodo y responde con un ACK firmado.
    CWE-20: Validación estricta vía Pydantic schema.
    """
    from src.bunker_abac_engine import ABACContext, abac_engine
    from src.bunker_exceptions import BunkerABACDeniedError

    client_ip = request.client.host if request.client else "127.0.0.1"

    # Evaluar contexto ABAC para el nodo
    context = ABACContext(
        username=payload.node_id,
        role="OPERATOR",
        ip_address=client_ip,
        geo_region="Comunidad Valenciana",
        network_zone="VLAN-SECURE",
        trust_score=100 if payload.tpm_integrity == "Valid" else 50,
        mfa_method="FIDO2",
    )

    try:
        await abac_engine.evaluate_context(context)
    except BunkerABACDeniedError as abac_exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"ABAC Denied for Node: {abac_exc!s}",
        )

    now = datetime.now(timezone.utc)

    # Construir mensaje de ACK
    ack_raw = f"{payload.node_id}:{payload.tpm_integrity}:{now.isoformat()}"
    ack_hash = _compute_hmac(ack_raw)

    # En producción: guardar en bunker_secops.nodes (upsert) y audit_trail

    return HeartbeatResponse(
        status="ACK",
        server_ts=now.isoformat(),
        ack_hash=ack_hash,
    )
