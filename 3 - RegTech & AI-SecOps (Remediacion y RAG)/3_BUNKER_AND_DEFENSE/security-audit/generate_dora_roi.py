import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
"""
generate_dora_roi.py - Generador del Registro de Información (RoI) de Proveedores TIC según DORA.

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículos 28 a 44 (Gestión del Riesgo de Terceros TIC).
- Estándares Técnicos de Regulación (ITS): EBA/ITS/2024/01 y EBA/RTS/2024/01.
- Plantillas Oficiales RoI: RT.01.01 (Entidades del grupo), RT.02.01 (Proveedores TIC),
  RT.03.01 (Contratos TIC), RT.04.01 (Funciones Esenciales/Importantes apoyadas).

Descripción:
------------
Este script escanea configuraciones o inventarios de proveedores TIC (Cloud, SaaS, APIs, Data Centers),
valida la completitud de la información de riesgo de terceros y exporta la estructura normalizada
del Registro de Información en formatos JSON y Markdown para ser reportada a las Autoridades
Competentes Nacionales (ANC) o Autoridades Europeas de Supervisión (AES).

Uso:
----
  python generate_dora_roi.py --input-config inventory.json --output-dir ./reports_roi
  python generate_dora_roi.py --generate-demo --output-dir ./demo_roi
"""

import argparse
import datetime
import json
import logging
import os
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
logger = logging.getLogger("DORA_RoI_Generator")


@dataclass
class ICTProvider:
    """Modelo de datos para Proveedor TIC (Plantilla RT.02.01)."""

    provider_id: str
    legal_name: str
    lei_code: Optional[str]  # Legal Entity Identifier
    country: str
    corporate_group: Optional[str]
    service_type: str  # Cloud, SaaS, Managed Security, Data Center, API
    criticality_assessment: str  # "Critical", "High", "Medium", "Low"
    is_critical_third_party: bool  # Designación CTPP por ESA (Art. 31)


@dataclass
class ICTContract:
    """Modelo de datos para Contrato TIC (Plantilla RT.03.01)."""

    contract_id: str
    provider_id: str
    contract_title: str
    start_date: str
    end_date: str
    notice_period_days: int
    governing_law: str
    data_location_country: str
    subcontracting_allowed: bool
    exit_strategy_tested: bool


@dataclass
class EssentialFunction:
    """Modelo de datos para Función Esencial apoyada (Plantilla RT.04.01)."""

    function_id: str
    function_name: str
    business_unit: str
    is_critical_function: bool
    supported_by_contract_ids: List[str]
    max_tolerable_downtime_hours: float
    rto_hours: float
    rpo_hours: float


@dataclass
class RegisterOfInformation:
    """Contenedor principal del Registro de Información (RoI) según EBA/ITS/2024/01."""

    entity_name: str
    entity_lei: str
    reporting_date: str
    providers: List[Dict[str, Any]] = field(default_factory=list)
    contracts: List[Dict[str, Any]] = field(default_factory=list)
    functions: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DORARoIGenerator:
    """Generador y validador del Registro de Información (RoI) DORA."""

    def __init__(self, entity_name: str, entity_lei: str):
        self.entity_name = entity_name
        self.entity_lei = entity_lei
        self.providers: List[ICTProvider] = []
        self.contracts: List[ICTContract] = []
        self.functions: List[EssentialFunction] = []

    def add_provider(self, provider: ICTProvider) -> None:
        """Añade un proveedor TIC validando campos obligatorios."""
        if not provider.provider_id or not provider.legal_name:
            raise ValueError("Provider ID y Legal Name son obligatorios (Art. 28(3)).")
        self.providers.append(provider)

    def add_contract(self, contract: ICTContract) -> None:
        """Añade un contrato TIC."""
        provider_ids = {p.provider_id for p in self.providers}
        if contract.provider_id not in provider_ids:
            logger.warning(
                f"Contrato {contract.contract_id} hace referencia a un proveedor no registrado: {contract.provider_id}"
            )
        self.contracts.append(contract)

    def add_function(self, function: EssentialFunction) -> None:
        """Añade una función esencial apoyada por TIC."""
        self.functions.append(function)

    def generate_roi_structure(self) -> RegisterOfInformation:
        """Compila la estructura estandarizada RoI DORA."""
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        critical_providers_count = sum(1 for p in self.providers if p.criticality_assessment.lower() in ("critical", "high") or p.is_critical_third_party)
        contracts_without_exit_plan = sum(1 for c in self.contracts if not c.exit_strategy_tested)

        meta = {
            "dora_framework_version": "UE 2022/2554",
            "its_version": "EBA/ITS/2024/01",
            "total_providers": len(self.providers),
            "critical_providers_count": critical_providers_count,
            "total_contracts": len(self.contracts),
            "contracts_missing_exit_strategy": contracts_without_exit_plan,
            "total_critical_functions": sum(1 for f in self.functions if f.is_critical_function),
            "generated_at": now_str,
        }

        return RegisterOfInformation(
            entity_name=self.entity_name,
            entity_lei=self.entity_lei,
            reporting_date=datetime.date.today().isoformat(),
            providers=[asdict(p) for p in self.providers],
            contracts=[asdict(c) for c in self.contracts],
            functions=[asdict(f) for f in self.functions],
            metadata=meta,
        )

    def export_json(self, output_path: Path) -> None:
        """Exporta la estructura RoI en formato JSON estandarizado."""
        roi_data = self.generate_roi_structure()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(roi_data), f, indent=2, ensure_ascii=False)
        logger.info(f"Registro de Información JSON exportado correctamente en: {output_path}")

    def export_markdown(self, output_path: Path) -> None:
        """Exporta un resumen ejecutivo del RoI en formato Markdown."""
        roi_data = self.generate_roi_structure()
        meta = roi_data.metadata

        md_content = f"""# Registro de Información de Proveedores TIC (DORA RoI)
**Entidad Financiera:** {self.entity_name}  
**Código LEI:** {self.entity_lei}  
**Fecha del Reporte:** {roi_data.reporting_date}  
**Normativa Aplicable:** Reglamento DORA (UE) 2022/2554 - Artículos 28 a 44 / EBA ITS 2024/01

---

## 1. Resumen Ejecutivo del Registro de Información (RoI)

- **Total de Proveedores TIC Registrados:** {meta['total_providers']}
- **Proveedores TIC Críticos / Alto Riesgo:** {meta['critical_providers_count']}
- **Total de Contratos TIC Vigilados:** {meta['total_contracts']}
- **Contratos sin Prueba de Estrategia de Salida (Art. 28.8):** {meta['contracts_missing_exit_strategy']} ⚠️
- **Funciones Esenciales/Críticas del Banco Soportadas:** {meta['total_critical_functions']}

---

## 2. Registro de Proveedores TIC (Plantilla RT.02.01)

| Provider ID | Nombre Legal | Código LEI | País | Tipo de Servicio | Criticidad | CTPP (Art 31) |
|-------------|--------------|------------|------|------------------|------------|---------------|
"""
        for p in self.providers:
            lei = p.lei_code if p.lei_code else "N/A"
            ctpp_str = "SÍ" if p.is_critical_third_party else "NO"
            md_content += f"| `{p.provider_id}` | {p.legal_name} | `{lei}` | {p.country} | {p.service_type} | **{p.criticality_assessment}** | {ctpp_str} |\n"

        md_content += """

---

## 3. Registro de Contratos TIC (Plantilla RT.03.01)

| Contrato ID | Proveedor ID | Ley Aplicable | Ubicación Datos | Subcontratación | Plan Salida Probado |
|-------------|--------------|---------------|------------------|-----------------|---------------------|
"""
        for c in self.contracts:
            sub_str = "Permitida" if c.subcontracting_allowed else "Prohibida"
            exit_str = "✅ SÍ" if c.exit_strategy_tested else "❌ PENDIENTE"
            md_content += f"| `{c.contract_id}` | `{c.provider_id}` | {c.governing_law} | {c.data_location_country} | {sub_str} | {exit_str} |\n"

        md_content += """

---

## 4. Funciones Esenciales Apoyadas por TIC (Plantilla RT.04.01)

| Función ID | Nombre Función | Unidad | Función Crítica | RTO (h) | RPO (h) | Max Downtime (h) |
|------------|----------------|--------|-----------------|---------|---------|------------------|
"""
        for f in self.functions:
            crit_str = "🔴 CRÍTICA" if f.is_critical_function else "🟡 REGULAR"
            md_content += f"| `{f.function_id}` | {f.function_name} | {f.business_unit} | {crit_str} | {f.rto_hours}h | {f.rpo_hours}h | {f.max_tolerable_downtime_hours}h |\n"

        md_content += f"""

---
*Generado automáticamente por `generate_dora_roi.py` el {meta['generated_at']}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Resumen Markdown del RoI exportado correctamente en: {output_path}")


def build_demo_generator() -> DORARoIGenerator:
    """Construye un generador con datos sintéticos para demostración y testing."""
    generator = DORARoIGenerator(
        entity_name="Banco Digital de Resiliencia S.A.",
        entity_lei="5493001KJTIIGC8Y1R12",
    )

    # Proveedores
    p1 = ICTProvider(
        provider_id="PROV-001",
        legal_name="Amazon Web Services EMEA SARL",
        lei_code="54930065F6F0K8838318",
        country="LU",
        corporate_group="Amazon Inc.",
        service_type="Cloud IaaS/PaaS",
        criticality_assessment="Critical",
        is_critical_third_party=True,
    )
    p2 = ICTProvider(
        provider_id="PROV-002",
        legal_name="Cloudflare Netherlands B.V.",
        lei_code="98450000000000000000",
        country="NL",
        corporate_group="Cloudflare Inc.",
        service_type="WAF & DDoS Mitigation",
        criticality_assessment="Critical",
        is_critical_third_party=True,
    )
    p3 = ICTProvider(
        provider_id="PROV-003",
        legal_name="SaaS Payment Gateway Systems S.L.",
        lei_code=None,
        country="ES",
        corporate_group=None,
        service_type="Payment API",
        criticality_assessment="High",
        is_critical_third_party=False,
    )
    generator.add_provider(p1)
    generator.add_provider(p2)
    generator.add_provider(p3)

    # Contratos
    c1 = ICTContract(
        contract_id="CTR-AWS-2024-01",
        provider_id="PROV-001",
        contract_title="AWS Cloud Infrastructure Enterprise Support",
        start_date="2023-01-01",
        end_date="2026-12-31",
        notice_period_days=90,
        governing_law="Luxembourg Law",
        data_location_country="EU (Ireland / Frankfurt)",
        subcontracting_allowed=True,
        exit_strategy_tested=True,
    )
    c2 = ICTContract(
        contract_id="CTR-CLD-2024-05",
        provider_id="PROV-002",
        contract_title="Cloudflare DDoS Enterprise Protection",
        start_date="2024-01-15",
        end_date="2027-01-15",
        notice_period_days=60,
        governing_law="Dutch Law",
        data_location_country="EU Union-wide",
        subcontracting_allowed=False,
        exit_strategy_tested=True,
    )
    c3 = ICTContract(
        contract_id="CTR-PAY-2023-09",
        provider_id="PROV-003",
        contract_title="PSD2 Payment Switch SLA Agreement",
        start_date="2023-06-01",
        end_date="2025-06-01",
        notice_period_days=30,
        governing_law="Spanish Law",
        data_location_country="Spain",
        subcontracting_allowed=True,
        exit_strategy_tested=False,
    )
    generator.add_contract(c1)
    generator.add_contract(c2)
    generator.add_contract(c3)

    # Funciones
    f1 = EssentialFunction(
        function_id="FUNC-PAY-01",
        function_name="Procesamiento de Pagos con Tarjeta y Bizum",
        business_unit="Banca de Particulares",
        is_critical_function=True,
        supported_by_contract_ids=["CTR-AWS-2024-01", "CTR-PAY-2023-09"],
        max_tolerable_downtime_hours=2.0,
        rto_hours=1.0,
        rpo_hours=0.25,
    )
    f2 = EssentialFunction(
        function_id="FUNC-CORE-02",
        function_name="Core Banking Ledger & Cuentas Corrientes",
        business_unit="Operaciones Centrales",
        is_critical_function=True,
        supported_by_contract_ids=["CTR-AWS-2024-01"],
        max_tolerable_downtime_hours=4.0,
        rto_hours=2.0,
        rpo_hours=0.0,
    )
    generator.add_function(f1)
    generator.add_function(f2)

    return generator


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generador del Registro de Información de Proveedores TIC (DORA RoI - Art. 28-44 / EBA ITS 2024/01)."
    )
    parser.add_argument(
        "--input-config",
        type=Path,
        help="Ruta al archivo JSON con el inventario de proveedores, contratos y funciones.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./dora_roi_reports"),
        help="Directorio donde se guardarán las evidencias JSON y Markdown (default: ./dora_roi_reports).",
    )
    parser.add_argument(
        "--generate-demo",
        action="store_true",
        help="Genera un Registro de Información completo con datos sintéticos demostrativos.",
    )

    args = parser.parse_args()

    if not args.input_config and not args.generate_demo:
        logger.error("Debe proporcionar --input-config <fichero.json> o activar --generate-demo.")
        parser.print_help()
        sys.exit(2)

    try:
        if args.generate_demo:
            logger.info("Modo demostración activado: Cargando datos sintéticos de prueba DORA RoI.")
            generator = build_demo_generator()
        else:
            if not args.input_config.exists():
                logger.error(f"El archivo de entrada no existe: {args.input_config}")
                sys.exit(1)

            with open(args.input_config, "r", encoding="utf-8") as f:
                data = json.load(f)

            generator = DORARoIGenerator(
                entity_name=data.get("entity_name", "Entidad No Especificada"),
                entity_lei=data.get("entity_lei", "00000000000000000000"),
            )

            for p_dict in data.get("providers", []):
                generator.add_provider(ICTProvider(**p_dict))
            for c_dict in data.get("contracts", []):
                generator.add_contract(ICTContract(**c_dict))
            for f_dict in data.get("functions", []):
                generator.add_function(EssentialFunction(**f_dict))

        output_json = args.output_dir / "dora_register_of_information.json"
        output_md = args.output_dir / "dora_register_of_information.md"

        generator.export_json(output_json)
        generator.export_markdown(output_md)

        logger.info("Iteración 1 completada con éxito. Evidencias generadas correctamente.")
        sys.exit(0)

    except Exception as e:
        logger.critical(f"Error inesperado al generar el Registro de Información DORA: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
