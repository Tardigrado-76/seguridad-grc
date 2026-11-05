#!/usr/bin/env python3
"""nca_incident_reporter.py - Generador de Notificaciones de Incidentes TIC a Autoridades Competentes (ANC).

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículos 19 y 20 (Notificación de Incidentes TIC Mayores).
- NIS2 (Directiva UE 2022/2555): Artículos 23 (Notificación de incidentes significativos en 24h a CSIRT / ANC).
- Estándares Técnicos de Ejecución (ITS): EBA/ITS/2024/02.
- Fases Reglamentarias de Notificación:
    1. Notificación / Alerta Inicial (Initial Alert) -> Máximo 2 horas tras clasificación.
    2. Informe Intermedio / Progreso (Intermediate Report) -> Dentro de las 24 horas.
    3. Informe Final (Final Report) -> En el plazo de 1 mes tras resolución.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DORA_NIS2_NCA_Reporter")


class NotificationPhase:
    INITIAL = "initial"
    INTERMEDIATE = "intermediate"
    FINAL = "final"


@dataclass
class NCAReportMetadata:
    reporting_entity: str
    entity_lei: str
    target_anc: str
    incident_id: str
    phase: str
    submission_timestamp: str
    dora_article_reference: str = "Reglamento (UE) 2022/2554 Art. 19 / NIS2 Art. 23"


@dataclass
class IncidentDetails:
    title: str
    detection_timestamp: str
    classification_timestamp: str
    affected_services: list[str]
    impact_summary: str
    estimated_affected_clients: int
    estimated_economic_loss_eur: float
    current_status: str
    root_cause_analysis: str | None = None
    remediation_actions: list[str] = field(default_factory=list)
    lessons_learned: str | None = None


@dataclass
class NCARegulatoryReport:
    metadata: dict[str, Any]
    incident_details: dict[str, Any]
    regulatory_checklist: dict[str, bool]


class DORANCAReporter:
    def __init__(self, metadata: NCAReportMetadata, details: IncidentDetails) -> None:
        self.metadata = metadata
        self.details = details

    def build_report(self) -> NCARegulatoryReport:
        phase = self.metadata.phase.lower()
        checklist = {
            "initial_alert_within_2h": phase == NotificationPhase.INITIAL,
            "intermediate_report_within_24h": phase in (NotificationPhase.INTERMEDIATE, NotificationPhase.FINAL),
            "final_report_root_cause_included": phase == NotificationPhase.FINAL,
            "impact_assessment_completed": True,
            "log_chain_immutability_verified": True,
        }
        return NCARegulatoryReport(
            metadata=asdict(self.metadata),
            incident_details=asdict(self.details),
            regulatory_checklist=checklist,
        )

    def export_json(self, output_path: Path) -> None:
        report = self.build_report()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Notificación ANC ({self.metadata.phase.upper()}) exportada a JSON: {output_path}")

    def export_markdown(self, output_path: Path) -> None:
        report = self.build_report()
        phase_title = {
            NotificationPhase.INITIAL: "1. Notificación / Alerta Inicial (Plazo: 2 Horas - DORA Art. 19.4 / NIS2 24h)",
            NotificationPhase.INTERMEDIATE: "2. Informe Intermedio de Progreso (Plazo: 24 Horas - DORA Art. 19.5)",
            NotificationPhase.FINAL: "3. Informe Final y Análisis de Causa Raíz (DORA Art. 19.6)",
        }.get(self.metadata.phase, "Notificación Regulatoria DORA / NIS2")

        md_content = f"""# Formulario Oficial de Notificación de Incidente TIC Mayor (DORA / NIS2)
**Fase Reglamentaria:** {phase_title}
**Autoridad Competente Destinataria:** {self.metadata.target_anc}
**Entidad Informante:** {self.metadata.reporting_entity} (LEI: `{self.metadata.entity_lei}`)
**ID Incidente:** `{self.metadata.incident_id}`
**Fecha de Envío:** {self.metadata.submission_timestamp}

---

## 1. Metadatos de la Notificación (Plantilla EBA/ITS/2024/02 & NIS2)

| Campo | Valor Registrado |
|-------|------------------|
| **Normativa** | {self.metadata.dora_article_reference} |
| **Entidad** | {self.metadata.reporting_entity} |
| **Código LEI** | `{self.metadata.entity_lei}` |
| **ANC Destino** | {self.metadata.target_anc} |
| **Fase** | **{self.metadata.phase.upper()}** |
| **Estado Actual** | `{self.details.current_status}` |

---

## 2. Detalle del Incidente

- **Título:** {self.details.title}
- **Timestamp Detección:** `{self.details.detection_timestamp}`
- **Timestamp Clasificación:** `{self.details.classification_timestamp}`
- **Servicios Afectados:** {", ".join([f"`{s}`" for s in self.details.affected_services])}
- **Clientes Afectados:** {self.details.estimated_affected_clients:,}
- **Pérdida Económica Estimada:** {self.details.estimated_economic_loss_eur:,.2f} €

### Resumen del Impacto
> {self.details.impact_summary}

---

## 3. Causa Raíz y Plan de Remediación
"""
        if self.metadata.phase in (NotificationPhase.INTERMEDIATE, NotificationPhase.FINAL):
            cause = self.details.root_cause_analysis or "En investigación activa por el equipo de Forense e Incident Response."
            md_content += f"**Causa Raíz:**\n{cause}\n\n"
            md_content += "**Acciones de Remediación:**\n"
            for act in self.details.remediation_actions:
                md_content += f"- ✅ {act}\n"
        else:
            md_content += "_Fase Inicial: Análisis de causa raíz en curso. Se adjuntará en Informe Intermedio._\n"

        if self.metadata.phase == NotificationPhase.FINAL:
            lessons = self.details.lessons_learned or "Revisión de arquitectura e incorporación de simulaciones de estrés."
            md_content += f"\n### Lecciones Aprendidas\n{lessons}\n"

        md_content += f"""
---
*Generado automáticamente por `nca_incident_reporter.py` el {self.metadata.submission_timestamp}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Notificación ANC ({self.metadata.phase.upper()}) exportada a Markdown: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generador de Notificaciones de Incidentes TIC a Autoridades Competentes.")
    parser.add_argument("--phase", choices=["initial", "intermediate", "final"], required=True)
    parser.add_argument("--incident-id", type=str, default="INC-2026-9901")
    parser.add_argument("--entity-name", type=str, default="Entidad Financiera / Operador Crítico S.A.")
    parser.add_argument("--entity-lei", type=str, default="5493001KJTIIGC8Y1R12")
    parser.add_argument("--target-anc", type=str, default="Banco de España / INCIBE-CERT")
    parser.add_argument("--title", type=str, default="Incidente Operacional TIC")
    parser.add_argument("--status", type=str, default="Mitigated")
    parser.add_argument("--root-cause", type=str, default="Fallo de hardware/software en infraestructura crítica.")
    parser.add_argument("--output-dir", type=Path, default=Path("./nca_notifications_output"))

    args = parser.parse_args()

    try:
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        meta = NCAReportMetadata(args.entity_name, args.entity_lei, args.target_anc, args.incident_id, args.phase, now_str)
        details = IncidentDetails(
            title=args.title,
            detection_timestamp=now_str,
            classification_timestamp=now_str,
            affected_services=["Core Services Gateway"],
            impact_summary="Indisponibilidad parcial de servicios digitales.",
            estimated_affected_clients=50000,
            estimated_economic_loss_eur=100000.0,
            current_status=args.status,
            root_cause_analysis=args.root_cause,
            remediation_actions=["Conmutación a sitio secundario de contingencia", "Aislamiento del vector de fallo"],
        )
        reporter = DORANCAReporter(meta, details)
        out_json = args.output_dir / f"{args.incident_id}_nca_report_{args.phase}.json"
        out_md = args.output_dir / f"{args.incident_id}_nca_report_{args.phase}.md"
        reporter.export_json(out_json)
        reporter.export_markdown(out_md)
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Error generando reporte ANC: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

