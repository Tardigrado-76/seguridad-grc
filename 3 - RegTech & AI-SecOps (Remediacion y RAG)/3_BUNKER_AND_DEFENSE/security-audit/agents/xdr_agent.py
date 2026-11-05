import asyncio
import logging

import psutil
from src.bunker_event_bus import EVENT_HONEYPOT_ALERT, BunkerEventBus

logger = logging.getLogger("BunkerOS.XDR")


class BunkerXDRAgent:
    """Agente de Extended Detection and Response (XDR).
    Monitorea de forma continua anomalías de endpoint:
    - Sockets abiertos no autorizados.
    - Procesos maliciosos conocidos (debuggers, sniffers).
    """

    SUSPICIOUS_PROCESSES = {
        "wireshark.exe",
        "tshark.exe",
        "tcpdump",
        "ida64.exe",
        "x64dbg.exe",
        "ollydbg.exe",
        "ghidra",
        "strace",
        "ltrace",
    }

    def __init__(self, check_interval_seconds=30) -> None:
        self.interval = check_interval_seconds
        self.bus = BunkerEventBus.get_instance()
        self._running = False

    def check_suspicious_processes(self) -> None:
        """Escanea todos los procesos en ejecución buscando software hostil."""
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info["name"]
                if pname and pname.lower() in self.SUSPICIOUS_PROCESSES:
                    logger.warning(
                        f"[XDR] Detección de proceso sospechoso: {pname}",
                    )
                    self.bus.publish(
                        EVENT_HONEYPOT_ALERT,
                        {
                            "reason": "MALICIOUS_PROCESS_DETECTED",
                            "process_name": pname,
                        },
                        source="XDRAgent",
                    )
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                pass

    def check_unauthorized_ports(self) -> None:
        """Busca puertos en escucha que no deberían estar abiertos."""
        # BunkerOS solo debería tener 8000, 8200 (Vault) y PostgreSQL local.
        # Si vemos un puerto extraño como 4444 (Metasploit) o nc.
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                port = conn.laddr.port
                if port in [4444, 4445, 1337, 31337]:
                    logger.warning(
                        f"[XDR] Puerto sospechoso en escucha: {port}",
                    )
                    self.bus.publish(
                        EVENT_HONEYPOT_ALERT,
                        {"reason": "UNAUTHORIZED_LISTENER", "port": port},
                        source="XDRAgent",
                    )

    async def run_loop(self) -> None:
        self._running = True
        logger.info(
            "[XDR] Agente iniciado. Monitorización de Endpoint activa.",
        )
        while self._running:
            try:
                self.check_suspicious_processes()
                self.check_unauthorized_ports()
            except (ValueError, TypeError, RuntimeError, OSError) as e:
                logger.exception(f"[XDR] Error en ciclo de escaneo: {e}")
            await asyncio.sleep(self.interval)

    def stop(self) -> None:
        self._running = False
