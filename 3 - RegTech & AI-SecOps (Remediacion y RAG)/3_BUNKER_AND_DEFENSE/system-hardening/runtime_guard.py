import asyncio
import contextlib
import os
import threading
import time

import psutil
from src.bunker_digital_suicide import execute_graceful_suicide
from src.bunker_logger import log_auditoria


def _sync_log(actor, action, details) -> None:
    with contextlib.suppress(ValueError, TypeError, RuntimeError, OSError):
        asyncio.run(log_auditoria(actor, action, details))


class BunkerRuntimeGuard:
    """Agente Supervisor de Seguridad en Tiempo de Ejecución (ETW/eBPF Mock).
    Detecta inyecciones de código (DLL Injection), volcados de memoria (Memory Dump),
    o manipulación del proceso host. Cumple con ENS op.mon.
    """

    def __init__(self) -> None:
        self.active = False
        self.pid = os.getpid()
        self.process = psutil.Process(self.pid)
        self.baseline_threads = self.process.num_threads()
        self.suspicious_libraries = ["dbghelp.dll", "minidump.dll"]

    def _guard_loop(self) -> None:
        _sync_log(
            "SYSTEM", "RUNTIME_GUARD_START", f"Runtime Guard iniciado en PID: {self.pid}",
        )
        while self.active:
            try:
                # 1. Detección de Thread Hijacking / Inyección de APC
                current_threads = self.process.num_threads()
                if current_threads > self.baseline_threads + 20:
                    _sync_log(
                        "CRITICAL",
                        "RUNTIME_ANOMALY",
                        f"Inyección de hilos detectada: {current_threads} hilos. Abortando.",
                    )
                    execute_graceful_suicide()

                # 2. Detección de Modulos Sospechosos (Anti-Dump / Anti-Debug)
                if os.name == "nt":
                    try:
                        maps = self.process.memory_maps()
                        for m in maps:
                            for bad_lib in self.suspicious_libraries:
                                if bad_lib in m.path.lower():
                                    _sync_log(
                                        "CRITICAL",
                                        "MEMORY_DUMP_ATTEMPT",
                                        f"Librería de volcado detectada: {bad_lib}. Self-Termination.",
                                    )
                                    execute_graceful_suicide()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                # 3. Monitorización de Fugas de Memoria (RGPD / NIS2)
                # Obtenemos el RSS (Resident Set Size) en bytes y convertimos a MB
                mem_info = self.process.memory_info()
                rss_mb = mem_info.rss / (1024 * 1024)

                WARNING_THRESHOLD_MB = 500
                CRITICAL_THRESHOLD_MB = 800

                if rss_mb > CRITICAL_THRESHOLD_MB:
                    _sync_log(
                        "CRITICAL",
                        "MEMORY_LEAK_CRITICAL",
                        f"Consumo de memoria crítico detectado: {rss_mb:.2f} MB. Abortando proceso para prevenir DoS/Exfiltración.",
                    )
                    execute_graceful_suicide()
                elif rss_mb > WARNING_THRESHOLD_MB:
                    _sync_log(
                        "WARNING",
                        "MEMORY_LEAK_WARNING",
                        f"Alto consumo de memoria detectado: {rss_mb:.2f} MB. Posible fuga.",
                    )

                time.sleep(2)  # Ciclo de evaluación continua
            except (ValueError, TypeError, RuntimeError, OSError) as e:
                _sync_log(
                    "WARNING",
                    "RUNTIME_GUARD_ERROR",
                    f"Error en loop de supervisión: {e}",
                )
                time.sleep(5)

    def start(self) -> None:
        self.active = True
        t = threading.Thread(target=self._guard_loop, daemon=True)
        t.start()


runtime_guard = BunkerRuntimeGuard()
