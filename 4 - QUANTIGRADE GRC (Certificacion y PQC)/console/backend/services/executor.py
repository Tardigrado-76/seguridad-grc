"""QUANTIGRADE GCR — ASYNC SSE EXECUTOR
Asynchronous non-blocking executor streaming subprocess output via Server-Sent Events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import AsyncGenerator
from pathlib import Path

from ..config.clients import (
    SCRIPTS_REGISTRY,
    get_interpreter_cmd,
    resolve_script_path,
)

logger = logging.getLogger("quantigrade_console.executor")

SCRIPT_TIMEOUT = int(os.getenv("SCRIPT_TIMEOUT_SECONDS", "300"))


def _sse_event(event: str, data: str | dict) -> str:
    if isinstance(data, dict):
        payload = json.dumps(data, ensure_ascii=False)
    else:
        payload = json.dumps({"line": data}, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"


def sse_log(line: str) -> str:
    return _sse_event("log", {"line": line.rstrip()})


def sse_status(status: str, message: str = "") -> str:
    return _sse_event("status", {"status": status, "message": message})


def sse_meta(client_id: str, script_id: str) -> str:
    script = SCRIPTS_REGISTRY.get(script_id, {})
    return _sse_event("meta", {
        "client_id": client_id,
        "script_id": script_id,
        "label": script.get("label", script_id),
        "risk_level": script.get("risk_level", "UNKNOWN"),
        "requires_admin": script.get("requires_admin", False),
    })


async def stream_script(
    client_id: str,
    script_id: str,
) -> AsyncGenerator[str, None]:
    try:
        script_path = resolve_script_path(client_id, script_id)
    except (KeyError, PermissionError, FileNotFoundError) as err:
        logger.warning("[AUTH] Rechazada ejecución de %s/%s: %s", client_id, script_id, err)
        yield sse_status("ERROR", str(err))
        return

    script_cfg = SCRIPTS_REGISTRY[script_id]
    interpreter_cmd = get_interpreter_cmd(script_cfg["interpreter"])
    cmd = interpreter_cmd + script_cfg.get("args", []) + [str(script_path)]

    yield sse_meta(client_id, script_id)
    yield sse_status("RUNNING", f"Iniciando {script_cfg['label']}...")

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(script_path.parent),
        )

        async def read_stream():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                yield line.decode("utf-8", errors="replace")

        try:
            async with asyncio.timeout(SCRIPT_TIMEOUT):
                async for line in read_stream():
                    yield sse_log(line)
        except TimeoutError:
            proc.kill()
            yield sse_status("ERROR", f"Timeout de ejecución excedido ({SCRIPT_TIMEOUT}s). Proceso terminado.")
            return

        exit_code = await proc.wait()
        if exit_code == 0:
            yield sse_status("DONE", "Ejecución completada con éxito.")
        else:
            yield sse_status("ERROR", f"Proceso finalizado con código de error {exit_code}.")

    except Exception as ex:
        logger.error("[EXEC] Excepción inesperada durante ejecución de %s: %s", script_id, ex, exc_info=True)
        yield sse_status("ERROR", f"Error interno del servidor: {ex}")

