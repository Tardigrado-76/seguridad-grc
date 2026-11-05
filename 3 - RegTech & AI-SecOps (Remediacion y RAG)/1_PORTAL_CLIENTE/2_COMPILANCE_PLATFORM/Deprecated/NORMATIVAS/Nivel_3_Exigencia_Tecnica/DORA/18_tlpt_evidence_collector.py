import logging
#!/usr/bin/env python3
"""
tlpt_evidence_collector.py - Recopilador de Evidencias TLPT y Calculador de MTTD/MTTR (DORA Art. 26).

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículo 26 (Pruebas de Penetración Basadas en Amenazas / TLPT / TIBER-EU).
- RTS EBA/RTS/2024/03 (Requisitos de Pruebas de Penetración Avanzadas).
- Objetivo: Recopilar y correlacionar evidencias de simulaciones de ciberataques (Red Team / Purple Team),
  evaluando cuantitativamente la capacidad de detección y respuesta del SOC mediante los indicadores MTTD y MTTR.

Descripción:
------------
Procesa eventos de simulaciones tácticas MITRE ATT&CK, correlaciona las alertas del SIEM/EDR del SOC,
calcula los tiempos medios de detección (MTTD) y respuesta (MTTR) y genera el paquete de evidencias.

Uso:
----
  python tlpt_evidence_collector.py --simulate-exercise --output-dir ./tlpt_evidences
  python tlpt_evidence_collector.py --events-file exercise_timeline.json --output-dir ./tlpt_evidences
"""

import argparse
import datetime
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DORA_TLPT_Collector")


@dataclass
class RedTeamAction:
    """Acción o técnica ejecutada por el Red Team."""

    action_id: str
    mitre_technique_id: str  # ej. T1059.001
    technique_name: str
    execution_timestamp: str
    target_asset: str


@dataclass
class SOCDetectionEvent:
    """Alerta o evento de detección registrado por el SOC/SIEM."""

    action_id: str
    detection_timestamp: str
    alert_severity: str  # CRITICAL, HIGH, MEDIUM
    detection_source: str  # EDR, SIEM, WAF, NTA
    response_timestamp: str
    contained_successfully: bool


@dataclass
class CorrelatedAttackStep:
    """Paso del ataque correlacionado entre Red Team y SOC."""

    action_id: str
    mitre_technique: str
    technique_name: str
    execution_time: str
    detection_time: Optional[str]
    response_time: Optional[str]
    time_to_detect_seconds: Optional[float]  # TTD
    time_to_respond_seconds: Optional[float]  # TTR
    detected: bool
    responded: bool


@dataclass
class TLPTEvidencePackage:
    """Paquete completo de evidencias TLPT DORA Art. 26."""

    exercise_id: str
    framework: str  # TIBER-EU / DORA TLPT
    exercise_date: str
    total_tactics_tested: int
    detected_tactics_count: int
    detection_rate_percentage: float
    mttd_minutes: float  # Mean Time to Detect
    mttr_minutes: float  # Mean Time to Respond
    correlated_steps: List[Dict[str, Any]]
    dora_tlpt_verdict: str


class DORATLPTCollector:
    """Recopilador y correlacionador de evidencias TLPT."""

    def __init__(self, exercise_id: str):
        self.exercise_id = exercise_id
        self.red_actions: List[RedTeamAction] = []
        self.soc_events: List[SOCDetectionEvent] = []

    def add_red_action(self, action: RedTeamAction) -> None:
        self.red_actions.append(action)

    def add_soc_event(self, event: SOCDetectionEvent) -> None:
        self.soc_events.append(event)

    def process_correlations(self) -> TLPTEvidencePackage:
        """Correlaciona las marcas de tiempo del Red Team con la respuesta del SOC."""
        soc_dict = {e.action_id: e for e in self.soc_events}
        correlated_steps: List[CorrelatedAttackStep] = []

        ttd_list: List[float] = []
        ttr_list: List[float] = []
        detected_count = 0

        for act in self.red_actions:
            soc_ev = soc_dict.get(act.action_id)
            
            exec_dt = datetime.datetime.fromisoformat(act.execution_timestamp.replace("Z", "+00:00"))

            if soc_ev:
                det_dt = datetime.datetime.fromisoformat(soc_ev.detection_timestamp.replace("Z", "+00:00"))
                resp_dt = datetime.datetime.fromisoformat(soc_ev.response_timestamp.replace("Z", "+00:00"))

                ttd_sec = max(0.0, (det_dt - exec_dt).total_seconds())
                ttr_sec = max(0.0, (resp_dt - det_dt).total_seconds())

                ttd_list.append(ttd_sec)
                ttr_list.append(ttr_sec)
                detected_count += 1

                step = CorrelatedAttackStep(
                    action_id=act.action_id,
                    mitre_technique=act.mitre_technique_id,
                    technique_name=act.technique_name,
                    execution_time=act.execution_timestamp,
                    detection_time=soc_ev.detection_timestamp,
                    response_time=soc_ev.response_timestamp,
                    time_to_detect_seconds=ttd_sec,
                    time_to_respond_seconds=ttr_sec,
                    detected=True,
                    responded=soc_ev.contained_successfully,
                )
            else:
                step = CorrelatedAttackStep(
                    action_id=act.action_id,
                    mitre_technique=act.mitre_technique_id,
                    technique_name=act.technique_name,
                    execution_time=act.execution_timestamp,
                    detection_time=None,
                    response_time=None,
                    time_to_detect_seconds=None,
                    time_to_respond_seconds=None,
                    detected=False,
                    responded=False,
                )

            correlated_steps.append(step)

        total_tested = len(self.red_actions)
        det_rate = (detected_count / total_tested * 100.0) if total_tested > 0 else 0.0

        mttd_min = (sum(ttd_list) / len(ttd_list) / 60.0) if ttd_list else 0.0
        mttr_min = (sum(ttr_list) / len(ttr_list) / 60.0) if ttr_list else 0.0

        # Umbrales TIBER-EU / DORA: Detección >= 70% y MTTD <= 45 minutos
        tlpt_pass = (det_rate >= 70.0) and (mttd_min <= 45.0)
        verdict = "TLPT_MATURITY_APPROVED" if tlpt_pass else "TLPT_MATURITY_NEEDS_IMPROVEMENT"

        return TLPTEvidencePackage(
            exercise_id=self.exercise_id,
            framework="DORA TLPT / TIBER-EU Framework",
            exercise_date=datetime.date.today().isoformat(),
            total_tactics_tested=total_tested,
            detected_tactics_count=detected_count,
            detection_rate_percentage=round(det_rate, 2),
            mttd_minutes=round(mttd_min, 2),
            mttr_minutes=round(mttr_min, 2),
            correlated_steps=[asdict(s) for s in correlated_steps],
            dora_tlpt_verdict=verdict,
        )

    def export_json(self, package: TLPTEvidencePackage, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(package), f, indent=2, ensure_ascii=False)
        logger.info(f"Paquete de Evidencias TLPT JSON exportado en: {output_path}")

    def export_markdown(self, package: TLPTEvidencePackage, output_path: Path) -> None:
        status_badge = "✅ EJERCICIO TLPT SUPERADO (CAPACIDAD SOC APTO)" if package.dora_tlpt_verdict == "TLPT_MATURITY_APPROVED" else "⚠️ REVISIÓN SOC REQUERIDA (DETECCIÓN / TIEMPOS INSOCIENTES)"

        md_content = f"""# Paquete de Evidencias de Pruebas de Penetración Avanzadas (TLPT / DORA Art. 26)

**ID Ejercicio Red/Purple Team:** `{package.exercise_id}`  
**Marco Regulatorio:** {package.framework}  
**Fecha de Realización:** {package.exercise_date}  
**Dictamen de Madurez SOC:** {status_badge}  

---

## 1. Indicadores Clave de Efectividad del SOC (MTTD / MTTR)

- **Total de Técnicas MITRE ATT&CK Ensayadas:** {package.total_tactics_tested}
- **Técnicas Detectadas por el SOC/SIEM:** {package.detected_tactics_count}
- **Tasa de Detección (Detection Rate):** **{package.detection_rate_percentage}%**
- **Tiempo Medio de Detección (MTTD):** **{package.mttd_minutes} minutos** ⏱️
- **Tiempo Medio de Respuesta / Contención (MTTR):** **{package.mttr_minutes} minutos** 🛡️

---

## 2. Correlación de Eventos (Red Team Exec vs SOC Alerts)

| ID Acción | Técnica MITRE | Nombre de la Técnica | Ejecutado (Red Team) | Detectado (SOC) | TTD (min) | TTR (min) | Estado |
|-----------|---------------|----------------------|----------------------|-----------------|-----------|-----------|--------|
"""
        for s in package.correlated_steps:
            status_str = "✅ DETECTADO" if s['detected'] else "🔴 NO DETECTADO"
            ttd_str = f"{s['time_to_detect_seconds']/60:.1f}m" if s['time_to_detect_seconds'] is not None else "N/A"
            ttr_str = f"{s['time_to_respond_seconds']/60:.1f}m" if s['time_to_respond_seconds'] is not None else "N/A"
            md_content += f"| `{s['action_id']}` | `{s['mitre_technique']}` | {s['technique_name']} | `{s['execution_time'][-8:]}` | `{s['detection_time'][-8:] if s['detection_time'] else 'N/A'}` | {ttd_str} | {ttr_str} | {status_str} |\n"

        md_content += f"""

---

## 3. Conformidad Regulatoria (DORA Art. 26)

> Las Pruebas de Penetración Basadas en Amenazas (TLPT) deben realizarse al menos cada 3 años
> sobre los sistemas de producción que soportan funciones esenciales. Las evidencias recopiladas
> demuestran la resiliencia operativa ante tácticas avanzadas de ciberataque.

---
*Generado por `tlpt_evidence_collector.py` el {package.exercise_date}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Informe de Evidencias TLPT Markdown exportado en: {output_path}")


def build_synthetic_exercise() -> DORATLPTCollector:
    """Construye un ejercicio TLPT sintético de prueba."""
    collector = DORATLPTCollector(exercise_id="TLPT-SIM-2026-EU01")
    now = datetime.datetime.now(datetime.timezone.utc)

    actions = [
        ("ACT-01", "T1059.001", "PowerShell Execution", 0, 8, 25),
        ("ACT-02", "T1003.001", "LSASS Memory Dumping", 30, 36, 50),
        ("ACT-03", "T1021.002", "SMB/Windows Admin Shares Lateral Movement", 60, 72, 90),
        ("ACT-04", "T1071.001", "Web Protocols C2 Communication", 90, 105, 120),
        ("ACT-05", "T1486", "Data Encrypted for Impact (Ransomware Sim)", 130, None, None),
    ]

    for act_id, mitre, name, offset_exec, offset_det, offset_resp in actions:
        exec_time = (now - datetime.timedelta(minutes=150 - offset_exec)).isoformat()
        collector.add_red_action(
            RedTeamAction(
                action_id=act_id,
                mitre_technique_id=mitre,
                technique_name=name,
                execution_timestamp=exec_time,
                target_asset="SRV-CORE-PROD-01",
            )
        )

        if offset_det is not None and offset_resp is not None:
            det_time = (now - datetime.timedelta(minutes=150 - offset_det)).isoformat()
            resp_time = (now - datetime.timedelta(minutes=150 - offset_resp)).isoformat()
            collector.add_soc_event(
                SOCDetectionEvent(
                    action_id=act_id,
                    detection_timestamp=det_time,
                    alert_severity="CRITICAL" if "LSASS" in name or "Ransomware" in name else "HIGH",
                    detection_source="CrowdStrike EDR / Splunk SIEM",
                    response_timestamp=resp_time,
                    contained_successfully=True,
                )
            )

    return collector


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recopilador de Evidencias de Pruebas de Penetración Avanzadas (TLPT / DORA Art. 26)."
    )
    parser.add_argument("--exercise-id", type=str, default="TLPT-SIM-2026-EU01", help="ID del ejercicio TLPT.")
    parser.add_argument("--simulate-exercise", action="store_true", help="Genera y procesa un ejercicio sintético de prueba.")
    parser.add_argument("--events-file", type=Path, help="Fichero JSON de entrada con cronología del ejercicio.")
    parser.add_argument("--output-dir", type=Path, default=Path("./tlpt_output"), help="Directorio de salida.")

    args = parser.parse_args()

    if not args.simulate_exercise and not args.events_file:
        logger.info("No se especificaron entradas. Ejecutando simulación sintética automáticamente.")
        args.simulate_exercise = True

    try:
        if args.simulate_exercise:
            collector = build_synthetic_exercise()
        else:
            collector = DORATLPTCollector(exercise_id=args.exercise_id)
            with open(args.events_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for r in data.get("red_actions", []):
                collector.add_red_action(RedTeamAction(**r))
            for s in data.get("soc_events", []):
                collector.add_soc_event(SOCDetectionEvent(**s))

        package = collector.process_correlations()

        out_json = args.output_dir / f"{package.exercise_id}_tlpt_package.json"
        out_md = args.output_dir / f"{package.exercise_id}_tlpt_package.md"

        collector.export_json(package, out_json)
        collector.export_markdown(package, out_md)

        logger.info(f"TLPT Evidences Processed. Detection Rate: {package.detection_rate_percentage}%, MTTD: {package.mttd_minutes}m, MTTR: {package.mttr_minutes}m.")
        sys.exit(0)

    except Exception as e:
        logger.critical(f"Error al procesar evidencias TLPT DORA: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
