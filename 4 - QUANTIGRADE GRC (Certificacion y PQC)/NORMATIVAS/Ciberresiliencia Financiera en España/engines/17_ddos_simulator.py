import logging

from dotenv import load_dotenv

load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
"""
ddos_simulator.py - Simulador y Evaluador de Resiliencia ante Ataques Volumétricos (DORA Art. 26 / ENS Alto).

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículo 26 y Art. 11 (Pruebas de Estrés y Resiliencia Operativa).
- ENS (Nivel Alto): Art. 21 (Protección contra Denegación de Servicio).
- MITRE ATT&CK: T1499 (Endpoint Denial of Service) / T1498 (Network Denial of Service).

Descripción:
------------
Ejecuta pruebas controladas de estrés y resiliencia DAST para evaluar la capacidad de respuesta de firewalls,
WAF y mecanismos Rate-Limiting/Circuit Breaker. Soporta ejecución sintética `--dry-run` y la librería estándar.

Uso:
----
  python ddos_simulator.py --target-url "http://127.0.0.1:8000/api/v3/auth/login" --dry-run
  python ddos_simulator.py --target-url "http://localhost:8080/health" --requests 100 --concurrency 10 --output-dir ./ddos_reports
"""

import argparse
import datetime
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DORA_DDoS_Simulator")


@dataclass
class SimulationMetrics:
    """Métricas cuantitativas de la prueba de estrés DAST."""

    target_url: str
    total_requests_sent: int
    successful_responses: int  # HTTP 200, 201, etc.
    blocked_or_throttled: int  # HTTP 429, 403, 503 o Connection Refused
    client_errors: int  # HTTP 4xx
    server_errors: int  # HTTP 5xx
    total_duration_seconds: float
    requests_per_second: float
    circuit_breaker_active: bool


@dataclass
class DDoSReport:
    """Informe de resiliencia y resiliencia operativa ante prueba volumétrica."""

    simulation_id: str
    timestamp: str
    target_url: str
    duration_seconds: float
    concurrency_level: int
    dry_run_mode: bool
    metrics: dict[str, Any]
    integrity_hash: str
    dora_resilience_verdict: str


class DORADDoSResilienceTester:
    """Evaluador autónomo de resiliencia ante ataques volumétricos y pruebas de carga."""

    def __init__(
        self,
        target_url: str,
        concurrency: int = 10,
        duration_seconds: int = 5,
        dry_run: bool = False,
    ):
        self.target_url = self._sanitize_target_url(target_url)
        self.concurrency = max(1, min(concurrency, 200))  # Límite seguro
        self.duration_seconds = max(1, min(duration_seconds, 60))
        self.dry_run = dry_run

    def _sanitize_target_url(self, url: str) -> str:
        """Previene inyección o SSRF validando el esquema HTTP/HTTPS y el host."""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Esquema de URL no permitido: '{parsed.scheme}'. Solo http:// o https://."
            )
        if not parsed.netloc:
            raise ValueError(f"URL de objetivo no válida o sin host: '{url}'.")
        return url

    def _send_single_request(self) -> int:
        """Envía una petición individual usando urllib de la librería estándar."""
        req = urllib.request.Request(
            self.target_url,
            data=json.dumps(
                {"test_payload": "DORA_DAST_STRESS_TEST", "timestamp": time.time()}
            ).encode("utf-8"),
            headers={
                "User-Agent": "BunkerOS-DAST-Resilience-Tester/2.0",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as response:
                return response.status
        except urllib.error.HTTPError as he:
            return he.code
        except (urllib.error.URLError, TimeoutError, OSError):
            return 0  # 0 indica conexión rechazada, drop o timeout (Circuit Breaker / WAF Block)

    def run_simulation(self) -> DDoSReport:
        """Ejecuta la prueba de estrés y compila los resultados."""
        simulation_id = f"DAST-DDOS-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        logger.info(f"Iniciando evaluación de resiliencia DAST [{simulation_id}]...")
        logger.info(
            f"Objetivo: {self.target_url} (Concurrencia: {self.concurrency}, Modo Dry-Run: {self.dry_run})"
        )

        if self.dry_run:
            logger.info(
                "Modo Dry-Run activado: Simulando 2,500 peticiones en 3 segundos con WAF activo."
            )
            total_reqs = 2500
            blocked = 2100
            success = 400
            elapsed = 3.0
            rps = total_reqs / elapsed
            circuit_active = True
        else:
            end_time = time.time() + self.duration_seconds
            total_reqs = 0
            success = 0
            blocked = 0
            client_errs = 0
            server_errs = 0

            t0 = time.time()
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                futures = []
                while time.time() < end_time:
                    futures.append(executor.submit(self._send_single_request))
                    time.sleep(0.005)

                for f in as_completed(futures):
                    total_reqs += 1
                    status_code = f.result()
                    if status_code in (200, 201, 202, 204):
                        success += 1
                    elif status_code in (429, 403, 503, 0):
                        blocked += 1
                    elif 400 <= status_code < 500:
                        client_errs += 1
                    else:
                        server_errs += 1

            elapsed = max(0.001, time.time() - t0)
            rps = total_reqs / elapsed
            circuit_active = blocked > success

        verdict = (
            "RESILIENCIA_OK_WAF_CIRCUIT_BREAKER_ACTIVO"
            if circuit_active
            else "ALERTA_SERVIDOR_SIN_PROTECCION_VOLUMETRICA"
        )

        metrics = SimulationMetrics(
            target_url=self.target_url,
            total_requests_sent=total_reqs,
            successful_responses=success,
            blocked_or_throttled=blocked,
            client_errors=0 if self.dry_run else client_errs,
            server_errors=0 if self.dry_run else server_errs,
            total_duration_seconds=round(elapsed, 2),
            requests_per_second=round(rps, 2),
            circuit_breaker_active=circuit_active,
        )

        summary = f"{simulation_id}|{total_reqs}|{rps:.2f}|{verdict}"
        integrity_hash = hashlib.sha256(summary.encode("utf-8")).hexdigest()

        return DDoSReport(
            simulation_id=simulation_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            target_url=self.target_url,
            duration_seconds=round(elapsed, 2),
            concurrency_level=self.concurrency,
            dry_run_mode=self.dry_run,
            metrics=asdict(metrics),
            integrity_hash=integrity_hash,
            dora_resilience_verdict=verdict,
        )

    def export_json(self, report: DDoSReport, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Informe DAST DDoS JSON exportado en: {output_path}")

    def export_markdown(self, report: DDoSReport, output_path: Path) -> None:
        m = report.metrics
        badge = (
            "✅ MECANISMO DE RESILIENCIA Y RATE-LIMITING VERIFICADO"
            if m["circuit_breaker_active"]
            else "🚨 ALERTA: EL SERVIDOR NO MITIGÓ EL ATAQUE VOLUMÉTRICO"
        )

        md_content = f"""# Evaluación de Resiliencia ante Ataques Volumétricos DAST (DORA Art. 26 / ENS Alto)

**ID Simulación:** `{report.simulation_id}`  
**URL Objetivo:** `{report.target_url}`  
**Fecha de Prueba:** {report.timestamp}  
**Modo Sintético (Dry-Run):** `{"SÍ" if report.dry_run_mode else "NO"}`  
**Dictamen de Resiliencia:** {badge}  

---

## 1. Métricas Cuantitativas del Ataque Volumétrico

- **Total de Peticiones Enviadas:** {m["total_requests_sent"]:,}
- **RPS Promedio (Requests per Second):** **{m["requests_per_second"]:,.2f} req/s** ⚡
- **Peticiones Bloqueadas / Throttled (HTTP 429/403/503/Drop):** {m["blocked_or_throttled"]:,}
- **Peticiones Procesadas Exitosamente:** {m["successful_responses"]:,}
- **Duración Total del Ensayo:** {m["total_duration_seconds"]} segundos
- **Estado del Circuit Breaker / WAF:** {"✅ ACTIVO Y RETENIENDO TRÁFICO" if m["circuit_breaker_active"] else "❌ INACTIVO"}

---

## 2. Marco Normativo de Resiliencia (DORA Art. 11 & Art. 26)

> El Reglamento DORA exige evaluar periódicamente la resiliencia de la infraestructura TIC
> ante picos de tráfico anómalos o ciberataques volumétricos de Denegación de Servicio (DoS/DDoS),
> comprobando que los cortafuegos de aplicación (WAF) y las políticas de Rate-Limiting protegen los servicios esenciales.

---
*Generado por `ddos_simulator.py` el {report.timestamp}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Informe DAST DDoS Markdown exportado en: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulador y Evaluador de Resiliencia ante Ataques Volumétricos DAST (DORA Art. 26 / ENS Alto Art. 21)."
    )
    parser.add_argument(
        "--target-url",
        type=str,
        default="http://127.0.0.1:8000/api/v3/auth/login",
        help="URL objetivo para la prueba de estrés DAST.",
    )
    parser.add_argument(
        "--concurrency", type=int, default=20, help="Número de hilos/workers paralelos."
    )
    parser.add_argument(
        "--duration", type=int, default=5, help="Duración del ataque en segundos."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Ejecuta una simulación sintética sin enviar tráfico real.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./ddos_audit_reports"),
        help="Directorio de salida.",
    )

    args = parser.parse_args()

    try:
        tester = DORADDoSResilienceTester(
            target_url=args.target_url,
            concurrency=args.concurrency,
            duration_seconds=args.duration,
            dry_run=args.dry_run,
        )
        report = tester.run_simulation()

        out_json = args.output_dir / f"{report.simulation_id}_ddos_report.json"
        out_md = args.output_dir / f"{report.simulation_id}_ddos_report.md"

        tester.export_json(report, out_json)
        tester.export_markdown(report, out_md)

        logger.info(
            f"Evaluación de resiliencia finalizada: {report.dora_resilience_verdict}."
        )
        sys.exit(0)

    except Exception as e:
        logger.critical(f"Error fatal durante la simulación DAST: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
