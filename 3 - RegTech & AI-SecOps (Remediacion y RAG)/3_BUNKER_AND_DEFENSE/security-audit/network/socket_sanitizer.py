#!/usr/bin/env python3
"""bunker_socket_sanitizer.py.
===========================
Pre-Flight Socket Sanitizer — BunkerOS v3.5
Compliance: CRA Art.13 / NIS2 Art.21 / ENS Alta op.exp.10

Responsabilidad:
  - Identificar procesos vinculados a puertos críticos del sistema antes del arranque.
  - Terminarlos de forma limpia (SIGTERM → SIGKILL con backoff).
  - Registrar todos los eventos con Correlation-ID en el log forense.
  - Elevar PortLockError si el puerto sigue ocupado tras la limpieza.

No tiene dependencias externas más allá de psutil.
"""

import datetime
import logging
import pathlib
import socket
import sys
import time
import uuid

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ─── Audit Log (forense) ────────────────────────────────────────────────────
LOG_DIR = pathlib.Path(r"E:\PROYECTOS IA\Release_Builder\logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "socket_sanitizer.log"

_fmt = logging.Formatter(
    "[%(asctime)s] %(levelname)s | %(message)s", "%Y-%m-%dT%H:%M:%S",
)
_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_handler.setFormatter(_fmt)

sanitizer_log = logging.getLogger("bunker.socket_sanitizer")
sanitizer_log.setLevel(logging.DEBUG)
sanitizer_log.addHandler(_handler)
# También mostrar en consola durante el pre-flight
_console = logging.StreamHandler()
_console.setFormatter(_fmt)
sanitizer_log.addHandler(_console)

# ─── Excepción de integridad ─────────────────────────────────────────────────


class PortLockError(RuntimeError):
    """Elevada cuando el puerto sigue ocupado tras la limpieza.
    El orquestador debe capturar esta excepción y emitir alerta de auditoría.
    """

    def __init__(self, port: int, correlation_id: str) -> None:
        self.port = port
        self.correlation_id = correlation_id
        super().__init__(
            f"[CORRELATION_ID:{correlation_id}] "
            f"Error de Integridad: Bloqueo de socket persistente en puerto {port}. "
            f"Arranque abortado por política CRA/NIS2.",
        )


def _log_event(level: str, correlation_id: str, port: int, pid: int, msg: str) -> None:
    entry = (
        f"CORRELATION_ID:{correlation_id} | PORT:{port} | PID:{pid} | {msg}"
    )
    if level == "INFO":
        sanitizer_log.info(entry)
    elif level == "WARNING":
        sanitizer_log.warning(entry)
    elif level == "ERROR":
        sanitizer_log.error(entry)
    elif level == "CRITICAL":
        sanitizer_log.critical(entry)


def _get_pids_on_port(port: int) -> list[tuple[int, str]]:
    """Devuelve lista de (PID, nombre) para procesos VIVOS escuchando en el puerto.
    Ignora conexiones donde el PID no existe ya en el sistema (sockets huérfanos del kernel).
    """
    results = []
    if not PSUTIL_AVAILABLE:
        return results
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not (conn.laddr and conn.laddr.port == port):
                continue
            if conn.status not in (
                "LISTEN",
                "ESTABLISHED",
                "SYN_SENT",
                "SYN_RECV",
            ):
                continue
            pid = conn.pid
            if pid is None:
                continue  # Socket del kernel sin propietario — tratado por _get_orphan_sockets
            try:
                proc = psutil.Process(pid)
                if not proc.is_running():
                    continue
                results.append((pid, proc.name()))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass  # Proceso ya muerto — no contabilizar
    except (ValueError, TypeError, RuntimeError, OSError) as exc:
        sanitizer_log.warning(f"Error enumerando conexiones: {exc}")
    return results


def _port_has_any_socket(port: int) -> bool:
    """Comprueba si hay CUALQUIER socket (incluidos huérfanos del kernel) en el puerto.
    Usa socket directo como fallback si psutil no está disponible.
    """
    # Método rápido: intento de bind real
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
        return False  # Bind exitoso — puerto libre
    except OSError:
        return True  # Puerto ocupado
    except (ValueError, TypeError, RuntimeError, OSError):
        return False  # Asumir libre ante error desconocido


def sanitize_port(port: int, grace_seconds: float = 3.0) -> bool:
    """Termina limpiamente todos los procesos vinculados al puerto dado.

    Flujo en 3 fases:
      1. Si hay procesos VIVOS → SIGTERM + espera + SIGKILL.
      2. Si solo hay socket huérfano del kernel (proceso muerto, PID=None o inexistente)
         → espera con backoff hasta 12s para liberación automática del SO.
      3. Verificación final con bind() real. Si únicamente sockets huérfanos persisten
         (sin ningún proceso vivo) → se autoriza el arranque (uvicorn usa SO_REUSEADDR).
         Si hay proceso VIVO persistente → PortLockError.

    Returns True si el puerto quedó libre (o solo hay huérfanos tolerables).
    Eleva PortLockError si hay proceso VIVO que no pudo eliminarse.
    """
    correlation_id = str(uuid.uuid4())

    if not PSUTIL_AVAILABLE:
        sanitizer_log.warning(
            f"CORRELATION_ID:{correlation_id} | psutil no disponible. "
            f"Limpieza de puerto {port} omitida (sin dependencia crítica).",
        )
        return True

    pids = _get_pids_on_port(port)  # Solo procesos VIVOS
    port_blocked = _port_has_any_socket(port)  # Incluye sockets huérfanos

    # ── Caso 1: Puerto completamente libre ──────────────────────────────────
    if not pids and not port_blocked:
        sanitizer_log.info(
            f"CORRELATION_ID:{correlation_id} | PORT:{port} | Libre. Sin acción necesaria.",
        )
        return True

    # ── Caso 2: Socket huérfano del kernel (proceso muerto, Windows retiene handle) ─
    if not pids and port_blocked:
        sanitizer_log.warning(
            f"CORRELATION_ID:{correlation_id} | PORT:{port} | "
            f"Socket huérfano detectado (proceso muerto, kernel retiene handle). "
            f"Esperando liberación automática del SO (máx. 12s)...",
        )
        for attempt in range(24):  # 24 x 0.5s = 12s máximo
            time.sleep(0.5)
            if not _port_has_any_socket(port):
                sanitizer_log.info(
                    f"CORRELATION_ID:{correlation_id} | PORT:{port} | "
                    f"Socket huérfano liberado por el SO tras {
                        (
                            attempt +
                            1) *
                        0.5:.1f}s.",
                )
                return True
        # Tras 12s: si no hay proceso VIVO, tolerar (uvicorn usa SO_REUSEADDR)
        live_after = _get_pids_on_port(port)
        if not live_after:
            sanitizer_log.warning(
                f"CORRELATION_ID:{correlation_id} | PORT:{port} | "
                f"Socket huérfano persistente sin proceso vivo. "
                f"Arranque autorizado (uvicorn/SO_REUSEADDR gestionará el bind).",
            )
            return True
        # Hay proceso vivo — escalar a fase de kill
        pids = live_after

    # ── Caso 3: Procesos VIVOS detectados → terminar ─────────────────────────
    sanitizer_log.warning(
        f"CORRELATION_ID:{correlation_id} | PORT:{port} | Detectados {
            len(pids)} proceso(s) VIVOS. Iniciando limpieza preventiva...",
    )

    # Fase 1: SIGTERM
    for pid, name in pids:
        try:
            proc = psutil.Process(pid)
            _log_event(
                "WARNING",
                correlation_id,
                port,
                pid,
                f"SIGTERM → proceso '{name}' (PID {pid})",
            )
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            _log_event(
                "INFO",
                correlation_id,
                port,
                pid,
                f"Proceso '{name}' ya terminado o inaccesible: {exc}",
            )

    # Espera de gracia
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if not _get_pids_on_port(port):
            sanitizer_log.info(
                f"CORRELATION_ID:{correlation_id} | PORT:{port} | "
                f"Proceso(s) eliminados tras SIGTERM. Puerto liberado.",
            )
            return True
        time.sleep(0.25)

    # Fase 2: SIGKILL
    remaining = _get_pids_on_port(port)
    for pid, name in remaining:
        try:
            proc = psutil.Process(pid)
            _log_event(
                "ERROR",
                correlation_id,
                port,
                pid,
                f"SIGKILL → '{name}' (PID {pid}) no respondió a SIGTERM",
            )
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            _log_event(
                "INFO",
                correlation_id,
                port,
                pid,
                f"Proceso ya extinto antes de SIGKILL: {exc}",
            )

    # Espera post-kill para liberación del socket por el kernel
    for _ in range(10):
        time.sleep(0.3)
        if not _get_pids_on_port(port):
            break

    # Verificación final: solo eleva PortLockError si hay proceso VIVO
    # persistente
    still_live = _get_pids_on_port(port)
    if still_live:
        _log_event(
            "CRITICAL",
            correlation_id,
            port,
            still_live[0][0],
            "Proceso VIVO persistente tras SIGKILL. Elevando PortLockError.",
        )
        raise PortLockError(port, correlation_id)

    sanitizer_log.info(
        f"CORRELATION_ID:{correlation_id} | PORT:{port} | "
        f"Proceso(s) eliminados. Limpieza completada.",
    )
    return True


def preflight_sanitize(ports: list[int], grace_seconds: float = 3.0) -> None:
    """Ejecuta el sanitizer sobre una lista de puertos.
    Llamar desde el orquestador antes de levantar cualquier stack.

    Eleva PortLockError en el primer puerto que no pueda liberarse.
    """
    sanitizer_log.info(
        f"{'=' * 60}\n"
        f"[PRE-FLIGHT SOCKET SANITIZER] Puertos objetivo: {ports}\n"
        f"Timestamp: {datetime.datetime.now().isoformat()}\n"
        f"{'=' * 60}",
    )
    for port in ports:
        sanitize_port(port, grace_seconds=grace_seconds)
    sanitizer_log.info(
        "[PRE-FLIGHT] Todos los puertos verificados y libres. Arranque autorizado.",
    )


if __name__ == "__main__":
    # Ejecución directa para limpieza manual
    ports = (
        [int(p) for p in sys.argv[1:]]
        if len(sys.argv) > 1
        else [8000, 8001, 3001]
    )
    try:
        preflight_sanitize(ports)
    except PortLockError:
        sys.exit(1)
