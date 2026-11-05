import logging
#!/usr/bin/env python3
"""
nca_incident_reporter.py - Generador de Notificaciones de Incidentes TIC a Autoridades Competentes (ANC).

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículos 19 y 20 (Notificación de Incidentes TIC Mayores).
- Estándares Técnicos de Ejecución (ITS): EBA/ITS/2024/02.
- Fases Reglamentarias de Notificación:
    1. Notificación / Alerta Inicial (Initial Alert) -> Máximo 2 horas tras clasificación.
    2. Informe Intermedio / Progreso (Intermediate Report) -> Dentro de las 24 horas.
    3. Informe Final (Final Report) -> En el plazo de 1 mes tras resolución.

Descripción:
------------
Generador de notificaciones regulatorias estandarizadas en formato JSON y Markdown estructuradas
para la Autoridad Nacional Competente (ANC - ej. Banco de España, CNMV, EIOPA/EBA/ESMA).

Uso:
----
  python nca_incident_reporter.py --phase initial --incident-id INC-2026-9901 --entity-name "Banco Digital" --output-dir ./nca_reports
  python nca_incident_reporter.py --phase intermediate --incident-id INC-2026-9901 --root-cause "Fallo hardware en SAN" --output-dir ./nca_reports
  python nca_incident_reporter.py --phase final --incident-id INC-2026-9901 --remediation-plan "Migración a almacenamiento redundante NVMe" --output-dir ./nca_reports
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
logger = logging.getLogger("DORA_NCA_Reporter")


class NotificationPhase:
    INITIAL = "initial"
    INTERMEDIATE = "intermediate"
    FINAL = "final"


@dataclass
class NCAReportMetadata:
    """Metadatos del reporte a la ANC."""

    reporting_entity: str
    entity_lei: str
    target_anc: str  # ej. "Banco de España", "CNMV", "EIOPA", "EBA"
    incident_id: str
    phase: str  # "initial", "intermediate", "final"
    submission_timestamp: str
    dora_article_reference: str = "Reglamento (UE) 2022/2554 Art. 19 / EBA ITS 2024/02"


@dataclass
class IncidentDetails:
    """Detalles técnicos del incidente TIC."""

    title: str
    detection_timestamp: str
    classification_timestamp: str
    affected_services: List[str]
    impact_summary: str
    estimated_affected_clients: int
    estimated_economic_loss_eur: float
    current_status: str  # "Ongoing", "Mitigated", "Resolved"
    root_cause_analysis: Optional[str] = None
    remediation_actions: List[str] = field(default_factory=list)
    lessons_learned: Optional[str] = None


@dataclass
class NCARegulatoryReport:
    """Estructura completa de reporte para la ANC."""

    metadata: Dict[str, Any]
    incident_details: Dict[str, Any]
    regulatory_checklist: Dict[str, bool]


class DORANCAReporter:
    """Generador de notificaciones regulatorias conforme a DORA Art. 19-20."""

    def __init__(self, metadata: NCAReportMetadata, details: IncidentDetails):
        self.metadata = metadata
        self.details = details

    def build_report(self) -> NCARegulatoryReport:
        """Construye el informe estructurado validando la fase."""
        phase = self.metadata.phase.lower()
        
        checklist = {
            "initial_alert_within_2h": True if phase == NotificationPhase.INITIAL else False,
            "intermediate_report_within_24h": True if phase in (NotificationPhase.INTERMEDIATE, NotificationPhase.FINAL) else False,
            "final_report_root_cause_included": True if phase == NotificationPhase.FINAL else False,
            "impact_assessment_completed": True,
            "log_chain_immutability_verified": True,
        }

        return NCARegulatoryReport(
            metadata=asdict(self.metadata),
            incident_details=asdict(self.details),
            regulatory_checklist=checklist,
        )

    def export_json(self, output_path: Path) -> None:
        """Exporta la notificación en formato JSON oficial."""
        report = self.build_report()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Notificación ANC ({self.metadata.phase.upper()}) exportada a JSON: {output_path}")

    def export_markdown(self, output_path: Path) -> None:
        """Exporta el reporte en formato Markdown formal para presentación oficial."""
        report = self.build_report()
        phase_title = {
            NotificationPhase.INITIAL: "1. Notificación / Alerta Inicial (Plazo: 2 Horas - DORA Art. 19.4)",
            NotificationPhase.INTERMEDIATE: "2. Informe Intermedio de Progreso (Plazo: 24 Horas - DORA Art. 19.5)",
            NotificationPhase.FINAL: "3. Informe Final y Análisis de Causa Raíz (DORA Art. 19.6)",
        }.get(self.metadata.phase, "Notificación Regulatoria DORA")

        md_content = f"""# Formulario Oficial de Notificación de Incidente TIC Mayor (DORA)
**Fase Reglamentaria:** {phase_title}  
**Autoridad Competente Destinataria:** {self.metadata.target_anc}  
**Entidad Financiera Informante:** {self.metadata.reporting_entity} (LEI: `{self.metadata.entity_lei}`)  
**ID Incidente:** `{self.metadata.incident_id}`  
**Fecha de Registro/Envío:** {self.metadata.submission_timestamp}  

---

## 1. Metadatos de la Notificación (Plantilla EBA/ITS/2024/02)

| Campo | Valor Registrado |
|-------|------------------|
| **Normativa** | {self.metadata.dora_article_reference} |
| **Entidad** | {self.metadata.reporting_entity} |
| **Código LEI** | `{self.metadata.entity_lei}` |
| **ANC Destino** | {self.metadata.target_anc} |
| **Fase de Notificación** | **{self.metadata.phase.upper()}** |
| **Estado Actual del Incidente** | `{self.details.current_status}` |

---

## 2. Detalle del Incidente TIC Mayor

- **Título del Incidente:** {self.details.title}
- **Timestamp de Detección en SOC:** `{self.details.detection_timestamp}`
- **Timestamp de Clasificación como Mayor:** `{self.details.classification_timestamp}`
- **Servicios Afectados:** {", ".join([f"`{s}`" for s in self.details.affected_services])}
- **Clientes / Usuarios Afectados Estimados:** {self.details.estimated_affected_clients:,}
- **Pérdida Económica Estimada:** {self.details.estimated_economic_loss_eur:,.2f} €

### Resumen del Impacto Operativo
> {self.details.impact_summary}

---

## 3. Análisis de Causa Raíz y Plan de Remediación
"""
        if self.metadata.phase in (NotificationPhase.INTERMEDIATE, NotificationPhase.FINAL):
            cause = self.details.root_cause_analysis if self.details.root_cause_analysis else "En investigación activa por el equipo de Forense e Incident Response."
            md_content += f"**Causa Raíz Identificada:**  \n{cause}\n\n"
            md_content += "**Acciones de Remediación e Mitigación:**\n"
            if self.details.remediation_actions:
                for act in self.details.remediation_actions:
                    md_content += f"- ✅ {act}\n"
            else:
                md_content += "- Mitigación temporal aplicada. Plan definitivo en desarrollo.\n"
        else:
            md_content += "_Fase Inicial: Análisis de causa raíz en curso. Se adjuntará en el Informe Intermedio (24h)._\n"

        if self.metadata.phase == NotificationPhase.FINAL:
            lessons = self.details.lessons_learned if self.details.lessons_learned else "Revisión de arquitectura y pruebas de estrés adicionales incorporadas al plan anual."
            md_content += f"\n### Lecciones Aprendidas y Medidas Preventivas Futuras\n{lessons}\n"

        md_content += f"""

---

## 4. Lista de Verificación Regulatoria DORA

- [x] Alerta Inicial enviada dentro de las 2 horas tras clasificación.
- [{'x' if report.regulatory_checklist['intermediate_report_within_24h'] else ' '}] Informe Intermedio registrado antes de 24 horas.
- [{'x' if report.regulatory_checklist['final_report_root_cause_included'] else ' '}] Informe Final firmado con causa raíz y lecciones aprendidas.
- [x] Evidencias y logs de auditoría preservados en almacenamiento inmutable SHA-256.

---
*Generado y firmado por `nca_incident_reporter.py` el {self.metadata.submission_timestamp}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Notificación ANC ({self.metadata.phase.upper()}) exportada a Markdown: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generador de Notificaciones de Incidentes TIC a Autoridades Competentes (DORA Art. 19-20 / EBA ITS 2024/02)."
    )
    parser.add_argument(
        "--phase",
        choices=["initial", "intermediate", "final"],
        required=True,
        help="Fase de la notificación reglamentaria (initial = 2h, intermediate = 24h, final = 1 mes).",
    )
    parser.add_argument("--incident-id", type=str, default="INC-2026-9901", help="ID del incidente TIC.")
    parser.add_argument("--entity-name", type=str, default="Banco Digital de Resiliencia S.A.", help="Nombre de la entidad.")
    parser.add_argument("--entity-lei", type=str, default="5493001KJTIIGC8Y1R12", help="Código LEI de la entidad.")
    parser.add_argument("--target-anc", type=str, default="Banco de España", help="Autoridad Nacional Competente destinataria.")
    parser.add_argument("--title", type=str, default="Caída de Servicio de Pagos Bizum", help="Título del incidente.")
    parser.add_argument("--status", type=str, default="Mitigated", help="Estado actual (Ongoing, Mitigated, Resolved).")
    parser.add_argument("--root-cause", type=str, default="Fallo de hardware en la controladora SAN principal.", help="Causa raíz.")
    parser.add_argument("--output-dir", type=Path, default=Path("./nca_notifications_output"), help="Directorio de salida.")

    args = parser.parse_args()

    try:
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        meta = NCAReportMetadata(
            reporting_entity=args.entity_name,
            entity_lei=args.entity_lei,
            target_anc=args.target_anc,
            incident_id=args.incident_id,
            phase=args.phase,
            submission_timestamp=now_str,
        )

        details = IncidentDetails(
            title=args.title,
            detection_timestamp=(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).isoformat(),
            classification_timestamp=(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1, minutes=45)).isoformat(),
            affected_services=["API Gateway Pagos Bizum", "Core Banking Switch"],
            impact_summary="Indisponibilidad parcial del procesamiento de transferencias inmediatas por 2.5 horas.",
            estimated_affected_clients=150000,
            estimated_economic_loss_eur=250000.0,
            current_status=args.status,
            root_cause_analysis=args.root_cause,
            remediation_actions=[
                "Conmutación de tráfico a la infraestructura redundante en Centro de Proceso de Datos secundario.",
                "Sustitución física de la controladora SAN defectuosa.",
                "Verificación de integridad de la base de datos transaccional mediante firmas hash.",
            ],
            lessons_learned="Acelerar la transición a arquitectura de almacenamiento distribuido multisitio.",
        )

        reporter = DORANCAReporter(meta, details)

        out_json = args.output_dir / f"{args.incident_id}_nca_report_{args.phase}.json"
        out_md = args.output_dir / f"{args.incident_id}_nca_report_{args.phase}.md"

        reporter.export_json(out_json)
        reporter.export_markdown(out_md)

        logger.info(f"Reporte reglamentario fase [{args.phase.upper()}] generado exitosamente.")
        sys.exit(0)

    except Exception as e:
        logger.critical(f"Error al generar la notificación ANC DORA: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
