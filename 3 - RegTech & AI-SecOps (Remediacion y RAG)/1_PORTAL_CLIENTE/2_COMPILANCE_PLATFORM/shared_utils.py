"""Utilidades compartidas para la plataforma Quantigrade.

Proporciona:
- Logging JSON estructurado conforme a DORA Art. 6 y ENS Alta mp.info.9.
- Ejecucion segura de herramientas CLI (Python y PowerShell).
- Sanitizacion de salida para evitar fugas de secretos en la UI.
- Timeouts adaptativos por tipo de herramienta.
"""

import json
import logging
import os
import re
import subprocess  # nosec B404
import uuid
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Constantes de Timeout Adaptativo
# ---------------------------------------------------------------------------
TIMEOUT_FAST_CLI = 30       # CLI ligera (lint, compile)
TIMEOUT_STANDARD = 120      # Auditoria estandar
TIMEOUT_HEAVY_AUDIT = 300   # Auditoria multi-normativa
TIMEOUT_AI_AGENT = 600      # Agente IA / LLM

# ---------------------------------------------------------------------------
# Patrones de secretos a sanitizar en stdout/stderr
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(sk-[A-Za-z0-9_-]{20,})", re.ASCII),               # OpenAI keys
    re.compile(r"(ghp_[A-Za-z0-9]{36,})", re.ASCII),                 # GitHub PATs
    re.compile(r"(AIza[A-Za-z0-9_-]{35})", re.ASCII),                # Google API keys
    re.compile(r"(AKIA[A-Z0-9]{16})", re.ASCII),                     # AWS access keys
    re.compile(r"(Bearer\s+[A-Za-z0-9._~+/=-]{20,})", re.ASCII),     # Bearer tokens
    re.compile(r"(api[_-]?key\s*[:=]\s*\S{10,})", re.IGNORECASE),    # Generic api_key=
    re.compile(r"(password\s*[:=]\s*\S{4,})", re.IGNORECASE),        # password= leaks
]


# ---------------------------------------------------------------------------
# Logging Estructurado JSON
# ---------------------------------------------------------------------------
class _JSONFormatter(logging.Formatter):
    """Formateador JSON conforme a DORA Art. 6 / ENS mp.info.9."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
            "trace_id": getattr(record, "trace_id", "N/A"),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])
        return json.dumps(entry, ensure_ascii=False)


def create_structured_logger(name: str) -> logging.Logger:
    """Crea un logger JSON estructurado.

    Args:
        name: Nombre del modulo que solicita el logger.

    Returns:
        logging.Logger con handler JSON en consola.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        level = os.environ.get("LOG_LEVEL", "INFO").upper()
        logger.setLevel(getattr(logging, level, logging.INFO))
        handler = logging.StreamHandler()
        handler.setFormatter(_JSONFormatter())
        logger.addHandler(handler)
    return logger


_logger = create_structured_logger("quantigrade.shared_utils")


# ---------------------------------------------------------------------------
# Sanitizacion de salida
# ---------------------------------------------------------------------------
def sanitize_output(text: str) -> str:
    """Elimina tokens, API keys y secretos de la salida.

    Args:
        text: Texto crudo de stdout/stderr.

    Returns:
        Texto con secretos sustituidos por [REDACTED].
    """
    if not text:
        return text
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


# ---------------------------------------------------------------------------
# Ejecucion segura de herramientas CLI (Python)
# ---------------------------------------------------------------------------
def run_cli_tool(
    cmd_list: list[str],
    timeout: int = TIMEOUT_STANDARD,
    sanitize: bool = True,
) -> dict[str, Any]:
    """Ejecuta un comando CLI y devuelve el resultado estructurado.

    Args:
        cmd_list: Lista de argumentos del comando.
        timeout: Timeout en segundos (por defecto 120s).
        sanitize: Si True, sanitiza la salida antes de devolver.

    Returns:
        dict con keys: returncode, stdout, stderr, success, duration_ms.
    """
    trace_id = uuid.uuid4().hex[:12]
    _logger.info(
        "CLI exec: %s (timeout=%ds, trace=%s)",
        cmd_list[0] if cmd_list else "?",
        timeout,
        trace_id,
        extra={"trace_id": trace_id},
    )
    start = datetime.now(timezone.utc)
    try:
        res = subprocess.run(  # nosec B603
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        duration_ms = int(
            (datetime.now(timezone.utc) - start).total_seconds() * 1000
        )
        stdout = sanitize_output(res.stdout) if sanitize else res.stdout
        stderr = sanitize_output(res.stderr) if sanitize else res.stderr

        level = logging.INFO if res.returncode == 0 else logging.WARNING
        _logger.log(
            level,
            "CLI done: rc=%d, duration=%dms, trace=%s",
            res.returncode,
            duration_ms,
            trace_id,
            extra={"trace_id": trace_id},
        )
        return {
            "returncode": res.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "success": res.returncode == 0,
            "duration_ms": duration_ms,
            "trace_id": trace_id,
        }
    except subprocess.TimeoutExpired:
        duration_ms = int(
            (datetime.now(timezone.utc) - start).total_seconds() * 1000
        )
        _logger.error(
            "CLI timeout after %ds: %s (trace=%s)",
            timeout,
            cmd_list,
            trace_id,
            extra={"trace_id": trace_id},
        )
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"Timeout: el comando excedio {timeout}s.",
            "success": False,
            "duration_ms": duration_ms,
            "trace_id": trace_id,
        }
    except FileNotFoundError:
        _logger.error(
            "CLI not found: %s (trace=%s)",
            cmd_list,
            trace_id,
            extra={"trace_id": trace_id},
        )
        return {
            "returncode": -2,
            "stdout": "",
            "stderr": f"Ejecutable no encontrado: {cmd_list[0] if cmd_list else '?'}",
            "success": False,
            "duration_ms": 0,
            "trace_id": trace_id,
        }
    except PermissionError:
        _logger.error(
            "CLI permission denied: %s (trace=%s)",
            cmd_list,
            trace_id,
            extra={"trace_id": trace_id},
        )
        return {
            "returncode": -3,
            "stdout": "",
            "stderr": "Permiso denegado. Puede requerir ejecucion como Administrador.",
            "success": False,
            "duration_ms": 0,
            "trace_id": trace_id,
        }
    except OSError as e:
        _logger.error(
            "CLI OS error: %s (trace=%s)",
            e,
            trace_id,
            extra={"trace_id": trace_id},
        )
        return {
            "returncode": -4,
            "stdout": "",
            "stderr": f"Error del sistema operativo: {e}",
            "success": False,
            "duration_ms": 0,
            "trace_id": trace_id,
        }


# ---------------------------------------------------------------------------
# Ejecucion segura de scripts PowerShell
# ---------------------------------------------------------------------------
def run_ps1_tool(
    script_path: str,
    args: list[str] | None = None,
    timeout: int = TIMEOUT_STANDARD,
    sanitize: bool = True,
) -> dict[str, Any]:
    """Ejecuta un script PowerShell de forma segura.

    Args:
        script_path: Ruta absoluta al script .ps1.
        args: Argumentos adicionales para el script.
        timeout: Timeout en segundos.
        sanitize: Si True, sanitiza la salida.

    Returns:
        dict con keys: returncode, stdout, stderr, success, duration_ms.
    """
    cmd: list[str] = [
        "powershell",
        "-ExecutionPolicy", "Bypass",
        "-NoProfile",
        "-NonInteractive",
        "-File", script_path,
    ]
    if args:
        cmd.extend(args)
    return run_cli_tool(cmd, timeout=timeout, sanitize=sanitize)
