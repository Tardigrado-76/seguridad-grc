import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
import os
#!/usr/bin/env python3
"""
dora_incident_classifier.py - Motor de Clasificación de Incidentes TIC Mayores según DORA.

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículos 17 a 23 (Gestión, Clasificación y Notificación de Incidentes TIC).
- RTS EBA/RTS/2024/02: Criterios y umbrales cuantitativos/cualitativos para la clasificación
  de incidentes TIC mayores y amenazas sustanciales.

Descripción:
------------
Calculadora y motor de reglas CLI que evalúa las métricas clave de un incidente operacional o de ciberseguridad
y determina automáticamente si se clasifica como "Incidente TIC Mayor" bajo los umbrales de DORA.

Uso:
----
  python dora_incident_classifier.py --clients-affected 150000 --downtime-hours 3.5 --economic-loss 250000 --critical-service --eu-countries 3
  python dora_incident_classifier.py --interactive
  python dora_incident_classifier.py --input-json incident_metrics.json --output-dir ./incident_reports
"""

import argparse
import datetime
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DORA_Incident_Classifier")


# Umbrales Oficiales EBA/RTS/2024/02
THRESHOLD_CLIENTS_PERCENTAGE = 10.0  # > 10% de clientes afectados
THRESHOLD_CLIENTS_ABSOLUTE = 100_000  # > 100.000 clientes o usuarios finales
THRESHOLD_DOWNTIME_HOURS_CRITICAL = 2.0  # > 2 horas indisponibilidad servicio crítico
THRESHOLD_ECONOMIC_LOSS_EUR = 100_000.0  # > 100.000 € impacto económico estimado
THRESHOLD_EU_COUNTRIES = 2  # Afectación en 2 o más Estados Miembros UE


@dataclass
class IncidentMetrics:
    """Métricas cuantitativas y cualitativas de un incidente TIC (RTS EBA/RTS/2024/02)."""

    incident_id: str
    title: str
    service_name: str
    is_critical_function: bool
    affected_clients_count: int
    total_clients_base: int
    downtime_hours: float
    economic_loss_eur: float
    geographical_spread_countries: int
    data_loss_integrity_compromised: bool
    confidentiality_breach: bool
    reputational_impact_high: bool


@dataclass
class ClassificationCriterionResult:
    """Resultado individual de un criterio de clasificación DORA."""

    criterion_name: str
    article_reference: str
    triggered: bool
    observed_value: Any
    threshold_value: Any
    justification: str


@dataclass
class ClassificationReport:
    """Informe final de clasificación de incidente TIC bajo DORA."""

    incident_id: str
    timestamp: str
    classification: str  # "MAJOR_ICT_INCIDENT", "SIGNIFICANT_INCIDENT", "MINOR_INCIDENT"
    is_major: bool
    mandatory_nca_notification: bool  # Notificación a la ANC obligatoria (Art. 19)
    notification_deadline_hours: Optional[float]
    criteria_triggered_count: int
    criteria_evaluations: List[Dict[str, Any]]
    metrics: Dict[str, Any]


class DORAIncidentClassifier:
    """Motor de clasificación de incidentes TIC conforme a DORA Art. 18 y RTS EBA/RTS/2024/02."""

    def __init__(self, metrics: IncidentMetrics):
        self.metrics = metrics

    def evaluate(self) -> ClassificationReport:
        """Evalúa los criterios de DORA y clasifica el incidente."""
        evaluations: List[ClassificationCriterionResult] = []

        # 1. Clientes y Usuarios Afectados (Art. 18(1)(a) & RTS Art. 1)
        percentage_affected = (
            (self.metrics.affected_clients_count / self.metrics.total_clients_base * 100.0)
            if self.metrics.total_clients_base > 0
            else 0.0
        )
        triggered_clients = (
            percentage_affected >= THRESHOLD_CLIENTS_PERCENTAGE
            or self.metrics.affected_clients_count >= THRESHOLD_CLIENTS_ABSOLUTE
        )
        evaluations.append(
            ClassificationCriterionResult(
                criterion_name="Clientes y Usuarios Afectados",
                article_reference="DORA Art. 18(1)(a) / RTS Art. 1",
                triggered=triggered_clients,
                observed_value=f"{self.metrics.affected_clients_count:,} ({percentage_affected:.2f}%)",
                threshold_value=f">= {THRESHOLD_CLIENTS_ABSOLUTE:,} o >= {THRESHOLD_CLIENTS_PERCENTAGE}%",
                justification=(
                    f"El número de clientes afectados ({self.metrics.affected_clients_count:,}) "
                    f"o el porcentaje ({percentage_affected:.2f}%) supera los umbrales de impacto masivo."
                    if triggered_clients
                    else "Porcentaje y número de clientes afectados dentro de límites normales."
                ),
            )
        )

        # 2. Duración e Indisponibilidad del Servicio (Art. 18(1)(b) & RTS Art. 2)
        triggered_downtime = (
            self.metrics.is_critical_function
            and self.metrics.downtime_hours >= THRESHOLD_DOWNTIME_HOURS_CRITICAL
        )
        evaluations.append(
            ClassificationCriterionResult(
                criterion_name="Duración e Indisponibilidad de Servicio Crítico",
                article_reference="DORA Art. 18(1)(b) / RTS Art. 2",
                triggered=triggered_downtime,
                observed_value=f"{self.metrics.downtime_hours:.2f} horas (Servicio Crítico: {self.metrics.is_critical_function})",
                threshold_value=f">= {THRESHOLD_DOWNTIME_HOURS_CRITICAL} horas en función esencial",
                justification=(
                    f"Servicio crítico en caída por {self.metrics.downtime_hours:.2f} horas (Umbral: {THRESHOLD_DOWNTIME_HOURS_CRITICAL}h)."
                    if triggered_downtime
                    else "Indisponibilidad acumulada por debajo del umbral crítico."
                ),
            )
        )

        # 3. Impacto Económico Directo e Indirecto (Art. 18(1)(c) & RTS Art. 3)
        triggered_economic = self.metrics.economic_loss_eur >= THRESHOLD_ECONOMIC_LOSS_EUR
        evaluations.append(
            ClassificationCriterionResult(
                criterion_name="Impacto Económico Directo e Indirecto",
                article_reference="DORA Art. 18(1)(c) / RTS Art. 3",
                triggered=triggered_economic,
                observed_value=f"{self.metrics.economic_loss_eur:,.2f} €",
                threshold_value=f">= {THRESHOLD_ECONOMIC_LOSS_EUR:,.2f} €",
                justification=(
                    f"Pérdidas estimadas de {self.metrics.economic_loss_eur:,.2f} € superan el umbral cuantitativo."
                    if triggered_economic
                    else "Impacto económico financiero no supera el umbral reglamentario."
                ),
            )
        )

        # 4. Extensión Geográfica (Art. 18(1)(d) & RTS Art. 4)
        triggered_geo = self.metrics.geographical_spread_countries >= THRESHOLD_EU_COUNTRIES
        evaluations.append(
            ClassificationCriterionResult(
                criterion_name="Extensión Geográfica transfronteriza",
                article_reference="DORA Art. 18(1)(d) / RTS Art. 4",
                triggered=triggered_geo,
                observed_value=f"{self.metrics.geographical_spread_countries} Estados Miembros UE",
                threshold_value=f">= {THRESHOLD_EU_COUNTRIES} países UE",
                justification=(
                    f"Incidente con impacto transfronterizo en {self.metrics.geographical_spread_countries} países de la Unión Europea."
                    if triggered_geo
                    else "Impacto limitado a ámbito local/nacional único."
                ),
            )
        )

        # 5. Compromiso de Integridad o Brecha de Confidencialidad (Art. 18(1)(e) & RTS Art. 5)
        triggered_data = self.metrics.data_loss_integrity_compromised or self.metrics.confidentiality_breach
        evaluations.append(
            ClassificationCriterionResult(
                criterion_name="Pérdida de Datos o Brecha de Confidencialidad",
                article_reference="DORA Art. 18(1)(e) / RTS Art. 5",
                triggered=triggered_data,
                observed_value=f"Integridad alterada: {self.metrics.data_loss_integrity_compromised}, Brecha: {self.metrics.confidentiality_breach}",
                threshold_value="Cualquier alteración no autorizada de datos críticos o exfiltración",
                justification=(
                    "Se ha detectado filtración de datos sensibles o pérdida irrecuperable de integridad."
                    if triggered_data
                    else "No se reportan alteraciones de datos ni exfiltración de confidencialidad."
                ),
            )
        )

        # Regla de Clasificación DORA (RTS Art. 9):
        # Un incidente es MAYOR si cumple el criterio de función crítica + al menos 2 umbrales adicionales,
        # O si supera cualquiera de los umbrales materiales principales (Clientes masivos o Pérdida económica > 100k + Caída de función esencial).
        triggered_count = sum(1 for e in evaluations if e.triggered)
        
        is_major = False
        if triggered_downtime and (triggered_clients or triggered_economic or triggered_geo or triggered_data):
            is_major = True
        elif triggered_count >= 2 and self.metrics.is_critical_function:
            is_major = True
        elif triggered_clients and triggered_economic:
            is_major = True

        if is_major:
            classification = "MAJOR_ICT_INCIDENT"
            nca_notify = True
            deadline_h = 2.0  # Alerta inicial obligatoria en 2 horas (Art. 19.4)
        elif triggered_count >= 1:
            classification = "SIGNIFICANT_INCIDENT"
            nca_notify = False
            deadline_h = None
        else:
            classification = "MINOR_INCIDENT"
            nca_notify = False
            deadline_h = None

        return ClassificationReport(
            incident_id=self.metrics.incident_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            classification=classification,
            is_major=is_major,
            mandatory_nca_notification=nca_notify,
            notification_deadline_hours=deadline_h,
            criteria_triggered_count=triggered_count,
            criteria_evaluations=[asdict(e) for e in evaluations],
            metrics=asdict(self.metrics),
        )

    def export_json(self, report: ClassificationReport, output_path: Path) -> None:
        """Exporta la evaluación a un archivo JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Reporte de Clasificación JSON exportado en: {output_path}")

    def export_markdown(self, report: ClassificationReport, output_path: Path) -> None:
        """Exporta la evaluación a un reporte Markdown ejecutivo."""
        badge = "🔴 INCIDENTE TIC MAYOR (MAJOR ICT INCIDENT)" if report.is_major else ("🟡 INCIDENTE SIGNIFICATIVO" if report.classification == "SIGNIFICANT_INCIDENT" else "🟢 INCIDENTE MENOR")
        
        md_content = f"""# Evaluación de Clasificación de Incidente TIC (DORA Art. 18)

**ID del Incidente:** `{report.incident_id}`  
**Fecha de Evaluación:** {report.timestamp}  
**Resultado de Clasificación DORA:** {badge}  
**Notificación Obligatoria a ANC (Banco de España / CNMV):** {"⚠️ OBLIGATORIA (Plazo: 2 horas)" if report.mandatory_nca_notification else "NO REQUERIDA"}  

---

## 1. Resumen de la Evaluación

- **Servicio Afectado:** {self.metrics.service_name} (Función Esencial/Crítica: `{self.metrics.is_critical_function}`)
- **Criterios DORA Activados:** {report.criteria_triggered_count} / 5
- **Reglamento Aplicable:** DORA (UE) 2022/2554 Art. 17-23 & EBA/RTS/2024/02

---

## 2. Desglose de Criterios y Umbrales Evaluados

| Criterio Evaluado | Referencia Reglamentaria | Estado | Valor Observado | Umbral Exigido | Justificación |
|-------------------|--------------------------|--------|-----------------|----------------|---------------|
"""
        for e in report.criteria_evaluations:
            status_icon = "🔴 DISPARADO" if e['triggered'] else "🟢 NORMAL"
            md_content += f"| **{e['criterion_name']}** | {e['article_reference']} | {status_icon} | `{e['observed_value']}` | {e['threshold_value']} | {e['justification']} |\n"

        md_content += f"""

---

## 3. Acciones Recomendadas y Siguientes Pasos

"""
        if report.is_major:
            md_content += """1. 🚨 **Activar Gabinete de Crisis e Incidentes TIC.**
2. ⏱️ **Notificación Inicial de Alerta (Fase 1):** Preparar y enviar reporte inicial a la Autoridad Competente en un plazo máximo de **2 horas** (Art. 19.4).
3. 🔒 **Registrar en el Bitácora Inmutable:** Asegurar que los logs de detección y respuesta se encuentren firmados en almacén WORM.
4. 📄 **Preparar Informe Intermedio (Fase 2):** Reporte de progreso en **24 horas**.
"""
        else:
            md_content += """1. ℹ️ Registrar el incidente en la bitácora interna de gestión de operaciones TIC.
2. 🔄 Monitorear la evolución por si métricas adicionales (duración, clientes) escalan al umbral de Incidente Mayor.
"""

        md_content += f"""
---
*Evaluado por `dora_incident_classifier.py` el {report.timestamp}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Reporte de Clasificación Markdown exportado en: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calculadora y Motor de Reglas de Clasificación de Incidentes TIC Mayores DORA (Art. 18 / EBA RTS 2024/02)."
    )
    parser.add_argument("--incident-id", type=str, default="INC-2026-8841", help="ID del incidente.")
    parser.add_argument("--title", type=str, default="Caída del Switch de Pagos Bizum", help="Título o descripción breve.")
    parser.add_argument("--service-name", type=str, default="API Gateway Pagos", help="Nombre del servicio TIC.")
    parser.add_argument("--critical-service", action="store_true", help="Indica si el servicio soporta una función esencial o crítica.")
    parser.add_argument("--clients-affected", type=int, default=120000, help="Número total de clientes o usuarios finales afectados.")
    parser.add_argument("--total-clients", type=int, default=800000, help="Base total de clientes de la entidad.")
    parser.add_argument("--downtime-hours", type=float, default=2.5, help="Horas continuas de indisponibilidad o degradación grave.")
    parser.add_argument("--economic-loss", type=float, default=180000.0, help="Impacto económico estimado en Euros.")
    parser.add_argument("--eu-countries", type=int, default=2, help="Número de Estados Miembros de la UE afectados.")
    parser.add_argument("--data-loss", action="store_true", help="Pérdida de integridad de datos registrada.")
    parser.add_argument("--confidentiality-breach", action="store_true", help="Exfiltración o brecha de confidencialidad de datos.")
    parser.add_argument("--input-json", type=Path, help="Fichero JSON de entrada con métricas del incidente.")
    parser.add_argument("--output-dir", type=Path, default=Path("./incident_classification_output"), help="Directorio de salida.")

    args = parser.parse_args()

    try:
        if args.input_json and args.input_json.exists():
            with open(args.input_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            metrics = IncidentMetrics(**data)
        else:
            metrics = IncidentMetrics(
                incident_id=args.incident_id,
                title=args.title,
                service_name=args.service_name,
                is_critical_function=args.critical_service or True,  # Default a True para prueba si no especificado
                affected_clients_count=args.clients_affected,
                total_clients_base=args.total_clients,
                downtime_hours=args.downtime_hours,
                economic_loss_eur=args.economic_loss,
                geographical_spread_countries=args.eu_countries,
                data_loss_integrity_compromised=args.data_loss,
                confidentiality_breach=args.confidentiality_breach,
                reputational_impact_high=True,
            )

        classifier = DORAIncidentClassifier(metrics)
        report = classifier.evaluate()

        out_json = args.output_dir / f"{report.incident_id}_classification.json"
        out_md = args.output_dir / f"{report.incident_id}_classification.md"

        classifier.export_json(report, out_json)
        classifier.export_markdown(report, out_md)

        logger.info(f"Clasificación realizada: {report.classification} (Major: {report.is_major}).")
        
        # Salida CLI con código 0 (éxito) o 1 (Incidente Mayor detectado)
        if report.is_major:
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        logger.critical(f"Error durante la clasificación del incidente: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
