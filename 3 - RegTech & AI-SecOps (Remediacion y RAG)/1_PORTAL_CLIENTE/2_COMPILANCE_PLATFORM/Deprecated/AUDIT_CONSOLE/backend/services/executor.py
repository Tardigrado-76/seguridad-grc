"""
╔══════════════════════════════════════════════════════════════════╗
║              AUDIT_CONSOLE — ASYNC SSE EXECUTOR                 ║
║  Motor de ejecución asíncrono no-bloqueante                     ║
║  Transmite stdout/stderr línea a línea via Server-Sent Events   ║
╚══════════════════════════════════════════════════════════════════╝

SEGURIDAD:
- asyncio.create_subprocess_exec con lista de args → SIN shell=True
- Comando construido desde SCRIPTS_REGISTRY (whitelist), nunca del usuario
- Timeout configurable vía SCRIPT_TIMEOUT_SECONDS
- SIGTERM graceful → SIGKILL si no termina en 5s
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


import asyncio
import json
import logging
import os
from pathlib import Path
from typing import AsyncGenerator

from config.clients import (
    SCRIPTS_REGISTRY,
    build_execution_command,
    resolve_script_path,
)

logger = logging.getLogger(__name__)

SCRIPT_TIMEOUT = int(os.getenv("SCRIPT_TIMEOUT_SECONDS", "300"))


# ──────────────────────────────────────────────────────────────────
# SSE EVENT HELPERS
# ──────────────────────────────────────────────────────────────────

def _sse_event(event: str, data: str | dict) -> str:
    """
    Formatea un evento SSE estándar.
    Format: "event: <type>\ndata: <json>\n\n"
    """
    if isinstance(data, dict):
        payload = json.dumps(data, ensure_ascii=False)
    else:
        payload = json.dumps({"line": data}, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"


def sse_log(line: str) -> str:
    """Evento de línea de log del proceso."""
    return _sse_event("log", {"line": line.rstrip()})


def sse_status(status: str, message: str = "") -> str:
    """Evento de cambio de estado: RUNNING | DONE | ERROR."""
    return _sse_event("status", {"status": status, "message": message})


def sse_meta(client_id: str, script_id: str) -> str:
    """Evento inicial con metadatos de la ejecución."""
    script = SCRIPTS_REGISTRY.get(script_id, {})
    return _sse_event("meta", {
        "client_id": client_id,
        "script_id": script_id,
        "label": script.get("label", script_id),
        "risk_level": script.get("risk_level", "UNKNOWN"),
        "requires_admin": script.get("requires_admin", False),
    })


# ──────────────────────────────────────────────────────────────────
# CORE EXECUTOR
# ──────────────────────────────────────────────────────────────────

async def stream_script(
    client_id: str,
    script_id: str,
) -> AsyncGenerator[str, None]:
    """
    Generador asíncrono que:
    1. Resuelve la ruta física del script de forma segura (Zero-Trust)
    2. Construye el comando desde la whitelist (nunca del usuario)
    3. Lanza el subprocess SIN shell=True
    4. Transmite stdout+stderr línea a línea como eventos SSE
    5. Emite evento de estado final (DONE/ERROR)

    Args:
        client_id: ID lógico o ruta del cliente (resuelto server-side)
        script_id: ID del script a ejecutar (whitelist)

    Yields:
        Strings en formato SSE ("event: ...\ndata: ...\n\n")
    """

    # ── 1. Resolución segura de ruta ──────────────────────────────
    try:
        script_path: Path = resolve_script_path(client_id, script_id)
    except (KeyError, PermissionError, FileNotFoundError) as exc:
        logger.error("[EXECUTOR] Resolución fallida: %s", exc)
        yield sse_status("ERROR", str(exc))
        return

    # ── 2. Construcción del comando (desde whitelist, sin user input) ──
    try:
        cmd = build_execution_command(script_id, script_path)
    except (KeyError, ValueError) as exc:
        logger.error("[EXECUTOR] Comando inválido: %s", exc)
        yield sse_status("ERROR", str(exc))
        return

    logger.info(
        "[EXECUTOR] Iniciando: client=%s script=%s cmd=%s",
        client_id, script_id, ' '.join(cmd[:3])
    )

    # ── 3. Metadatos iniciales ──────────────────────────────────────
    yield sse_meta(client_id, script_id)
    yield sse_status("RUNNING", f"Ejecutando: {SCRIPTS_REGISTRY[script_id]['label']}")
    yield sse_log(f"▶ CMD: {' '.join(cmd[:3])} ...")
    yield sse_log(f"▶ TARGET DIRECTORY: {client_id}")
    yield sse_log("─" * 60)

    # ── 4. Launch subprocess (SIN shell=True) ─────────────────────
    process: asyncio.subprocess.Process | None = None
    exit_code: int = -1

    # Asegurarnos que el target path existe para el CWD
    target_cwd = client_id
    if not os.path.exists(target_cwd) or not os.path.isdir(target_cwd):
        target_cwd = str(script_path.parent) # Fallback si falla
        yield sse_log(f"⚠ WARNING: Ruta destino '{client_id}' no encontrada. Usando {target_cwd}")

    sub_env = os.environ.copy()
    sub_env["PYTHONIOENCODING"] = "utf-8"
    sub_env["PYTHONUTF8"] = "1"
    sub_env["PYTHONUNBUFFERED"] = "1"

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=target_cwd,
            env=sub_env,
        )

        # ── 5. Stream línea a línea ─────────────────────────────────
        assert process.stdout is not None

        try:
            async with asyncio.timeout(SCRIPT_TIMEOUT):
                async for raw_line in process.stdout:
                    try:
                        line = raw_line.decode("utf-8", errors="replace")
                    except Exception:
                        line = repr(raw_line)
                    yield sse_log(line)

        except TimeoutError:
            logger.warning("[EXECUTOR] Timeout (%ss) alcanzado para %s", SCRIPT_TIMEOUT, script_id)
            yield sse_log(f"⚠ TIMEOUT: el script superó {SCRIPT_TIMEOUT}s. Terminando proceso...")
            if process and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except TimeoutError:
                    process.kill()
            yield sse_status("ERROR", f"Script terminado por timeout ({SCRIPT_TIMEOUT}s)")
            return

        exit_code = await process.wait()

    except Exception as exc:
        logger.exception("[EXECUTOR] Error inesperado ejecutando %s: %s", script_id, exc)
        yield sse_log(f"✗ ERROR INTERNO: {exc}")
        yield sse_status("ERROR", f"Error interno del executor: {exc}")
        return

    # ── 6. Estado final ────────────────────────────────────────────
    yield sse_log("─" * 60)

    if exit_code == 0:
        logger.info("[EXECUTOR] %s completado OK (exit=0)", script_id)
        yield sse_log(f"✓ Proceso finalizado correctamente (exit code: {exit_code})")
        yield sse_status("DONE", "Ejecución completada con éxito")
    else:
        logger.warning("[EXECUTOR] %s finalizó con error (exit=%d)", script_id, exit_code)
        yield sse_log(f"✗ Proceso terminó con errores (exit code: {exit_code})")
        yield sse_status("ERROR", f"El script finalizó con código de error: {exit_code}")


if __name__ == '__main__':
    # Production entry point
    pass
