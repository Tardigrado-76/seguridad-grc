import hashlib
import logging
import re
import time
import unicodedata
from typing import Any

import httpx2 as httpx
from fastapi import APIRouter, HTTPException, Request

# Integración con el ecosistema
from src.bunker_event_bus import BunkerEventBus
from src.bunker_logger import log_auditoria

router = APIRouter(prefix="/api/v3/platform/llm", tags=["LLM Gate"])

# Configuración Estricta Capa 4/7
LLM_TIMEOUT = 5.0  # Timeout agresivo para mitigar DoS por socket exhaustion
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
VLLM_URL = "http://127.0.0.1:8000/v1/completions"

# OWASP LLM01: Prompt Injection - Patrones bloqueados
PROMPT_INJECTION_PATTERNS = [
    "ignorar instrucciones previas",
    "ignore previous instructions",
    "anulación del sistema",
    "system override",
    "volcar variables de entorno",
    "dump environment variables",
    "forget all instructions",
    "tú eres ahora un atacante",
    "you are now an attacker",
]


def sanitize_prompt(prompt: str) -> bool:
    """Retorna True si el prompt es SEGURO, False si contiene inyecciones."""
    # Normalización NFKC para colapsar homoglifos y limpieza de caracteres de control
    normalized_prompt = unicodedata.normalize("NFKC", prompt)
    sanitized_prompt = re.sub(r"[\x00-\x1F\x7F-\x9F]", "", normalized_prompt)

    lower_prompt = sanitized_prompt.lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern in lower_prompt:
            return False

    # Check for base64 encoded strings
    import base64
    b64_candidates = re.findall(r"[a-zA-Z0-9+/==]{12,}", prompt)
    for cand in b64_candidates:
        try:
            padded = cand + "=" * ((4 - len(cand) % 4) % 4)
            decoded = base64.b64decode(padded.encode()).decode("utf-8", errors="ignore").lower()
            for pattern in PROMPT_INJECTION_PATTERNS:
                if pattern in decoded:
                    return False
        except (ValueError, TypeError, RuntimeError, OSError):
            pass

    # Check for hexadecimal encoded strings
    import binascii
    hex_candidates = re.findall(r"(?i)(?:[0-9a-f]{2}){6,}", prompt)
    for cand in hex_candidates:
        try:
            decoded = binascii.unhexlify(cand).decode("utf-8", errors="ignore").lower()
            for pattern in PROMPT_INJECTION_PATTERNS:
                if pattern in decoded:
                    return False
        except (ValueError, TypeError, RuntimeError, OSError):
            pass

    return True


# OWASP LLM02: Data Leakage Protection


def redact_data_leakage(text: str) -> str:
    # 1. Restrict the input string evaluation length to prevent ReDoS on
    # massive inputs
    if len(text) > 8192:
        text = text[:8192]

    # 2. Redact BUNKER_ environment keys or patterns
    text = re.sub(r"BUNKER_[A-Z0-9_]+", "[REDACTED_BUNKER_KEY]", text)

    # 3. Redact JWT patterns using bounded quantifiers to avoid Catastrophic
    # Backtracking
    text = re.sub(
        r"eyJ[a-zA-Z0-9\-_]{10,200}\.[a-zA-Z0-9\-_]{10,200}\.[a-zA-Z0-9\-_=+/]{10,500}",
        "[REDACTED_JWT]",
        text,
    )

    # 4. Redact hexadecimal strings of 32+ characters
    return re.sub(r"\b[0-9a-fA-F]{32,}\b", "[REDACTED_HEX_KEY]", text)



def evaluar_payload_inferencia(model: str, prompt: str) -> dict:
    import re

    # Heurística de ofuscación semántica
    if re.search(
        r"(?i)(base64|hex|rot13|encoding|ignore|bypas|system\s+prompt)", prompt,
    ):
        prompt = "Mensaje neutralizado por heurística semántica de inyección."
    return {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "num_predict": 256,
        "max_tokens": 256,
    }


def sanitize_response_data(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: sanitize_response_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_response_data(item) for item in data]
    if isinstance(data, str):
        return redact_data_leakage(data)
    return data


async def execute_local_inference(
    model: str, prompt: str, engine: str = "ollama",
) -> dict[str, Any]:
    """Ejecuta inferencia segura a través de httpx.AsyncClient con restricciones mTLS/Loopback.
    Incluye telemetría y auditoría forense (UNE 71505 / ENS Alta).
    """
    # 1. OWASP Top 10 LLM: Interceptor de Inyección
    if not sanitize_prompt(prompt):
        # Disparar alerta al bus de eventos
        try:
            bus = BunkerEventBus()
            bus.publish(
                "LLM_INJECTION_ATTEMPT",
                {
                    "model": model,
                    "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(),
                },
            )
        except (ValueError, TypeError, RuntimeError, OSError) as e:
            logging.exception(f"[LLM Gate] Error publishing to EventBus: {e}")

        # Auditoría de custodia forense
        await log_auditoria(
            "SYSTEM",
            "LLM_INJECTION_BLOCKED",
            f"Intento de inyección bloqueado para el modelo {model}",
            capec_id="CAPEC-673",
        )
        raise HTTPException(
            status_code=403,
            detail="LLM Prompt Injection Detected. Access Forbidden.",
        )

    # 2. Hardening L4: Configuración de Cliente Seguro
    # Uso explícito de timeout para evitar agotamiento de recursos locales
    target_url = OLLAMA_URL if engine == "ollama" else VLLM_URL
    payload = evaluar_payload_inferencia(model, prompt)

    start_time = time.perf_counter()
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()

    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            response = await client.post(target_url, json=payload)
            response.raise_for_status()
            data = response.json()

            # 3. Registro de Custodia Forense (ENS Alta / UE AI Act)
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            resource_footprint = f"{elapsed_ms:.2f}ms"

            # Apply OWASP LLM02: Data Leakage Redaction
            sanitized_data = sanitize_response_data(data)

            await log_auditoria(
                "SYSTEM",
                "LLM_INFERENCE_SUCCESS",
                f"Model ID: {model} | Prompt Hash: {prompt_hash} | Resource Footprint: {resource_footprint}",
            )
            return sanitized_data

    except httpx.TimeoutException:
        await log_auditoria(
            "SYSTEM",
            "LLM_INFERENCE_TIMEOUT",
            f"Model ID: {model} | Prompt Hash: {prompt_hash}",
        )
        raise HTTPException(
            status_code=504,
            detail="Inference timeout (Resource exhaustion protected).",
        )
    except httpx.RequestError as exc:
        await log_auditoria(
            "SYSTEM", "LLM_INFERENCE_ERROR", f"Model ID: {model} | Error: {
                exc!s}",
        )
        raise HTTPException(
            status_code=502,
            detail="Error communicating with local inference engine.",
        )


@router.post("/infer")
async def infer_endpoint(request: Request):
    """Punto de entrada de inferencia asíncrona unificado."""
    body = await request.json()
    model = body.get("model", "llama3")
    prompt = body.get("prompt", "")
    engine = body.get("engine", "ollama")

    if not prompt:
        raise HTTPException(status_code=400, detail="Empty prompt.")

    result = await execute_local_inference(model, prompt, engine)
    return {"status": "success", "data": result}
