#!/usr/bin/env python3
"""generate_dora_roi.py - Generador del Registro de Información (RoI) de Proveedores TIC según DORA.

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículos 28 a 44 (Gestión del Riesgo de Terceros TIC).
- Estándares Técnicos de Regulación (ITS): EBA/ITS/2024/01 y EBA/RTS/2024/01.
- Plantillas Oficiales RoI: RT.01.01 (Entidades del grupo), RT.02.01 (Proveedores TIC),
  RT.03.01 (Contratos TIC), RT.04.01 (Funciones Esenciales/Importantes apoyadas).
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
logger = logging.getLogger("DORA_RoI_Generator")


@dataclass
class ICTProvider:
    provider_id: str
    legal_name: str
    lei_code: str | None
    country: str
    corporate_group: str | None
    service_type: str
    criticality_assessment: str
    is_critical_third_party: bool


@dataclass
class ICTContract:
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
    function_id: str
    function_name: str
    business_unit: str
    is_critical_function: bool
    supported_by_contract_ids: list[str]
    max_tolerable_downtime_hours: float
    rto_hours: float
    rpo_hours: float


@dataclass
class RegisterOfInformation:
    entity_name: str
    entity_lei: str
    reporting_date: str
    providers: list[dict[str, Any]] = field(default_factory=list)
    contracts: list[dict[str, Any]] = field(default_factory=list)
    functions: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class DORARoIGenerator:
    def __init__(self, entity_name: str, entity_lei: str) -> None:
        self.entity_name = entity_name
        self.entity_lei = entity_lei
        self.providers: list[ICTProvider] = []
        self.contracts: list[ICTContract] = []
        self.functions: list[EssentialFunction] = []

    def add_provider(self, provider: ICTProvider) -> None:
        if not provider.provider_id or not provider.legal_name:
            raise ValueError("Provider ID y Legal Name son obligatorios (Art. 28(3)).")
        self.providers.append(provider)

    def add_contract(self, contract: ICTContract) -> None:
        provider_ids = {p.provider_id for p in self.providers}
        if contract.provider_id not in provider_ids:
            logger.warning(f"Contrato {contract.contract_id} referencia a proveedor no registrado: {contract.provider_id}")
        self.contracts.append(contract)

    def add_function(self, function: EssentialFunction) -> None:
        self.functions.append(function)

    def generate_roi_structure(self) -> RegisterOfInformation:
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
        roi_data = self.generate_roi_structure()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(roi_data), f, indent=2, ensure_ascii=False)
        logger.info(f"Registro de Información JSON exportado correctamente en: {output_path}")

    def export_markdown(self, output_path: Path) -> None:
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
            lei = p.lei_code or "N/A"
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
    generator = DORARoIGenerator(
        entity_name="Banco Digital de Resiliencia S.A.",
        entity_lei="5493001KJTIIGC8Y1R12",
    )
    generator.add_provider(ICTProvider("PROV-001", "Amazon Web Services EMEA SARL", "54930065F6F0K8838318", "LU", "Amazon Inc.", "Cloud IaaS/PaaS", "Critical", True))
    generator.add_provider(ICTProvider("PROV-002", "Cloudflare Netherlands B.V.", "98450000000000000000", "NL", "Cloudflare Inc.", "WAF & DDoS Mitigation", "Critical", True))
    generator.add_contract(ICTContract("CTR-AWS-2024-01", "PROV-001", "AWS Cloud Infrastructure Enterprise Support", "2023-01-01", "2026-12-31", 90, "Luxembourg Law", "EU (Frankfurt)", True, True))
    generator.add_contract(ICTContract("CTR-CLD-2024-05", "PROV-002", "Cloudflare DDoS Enterprise Protection", "2024-01-15", "2027-01-15", 60, "Dutch Law", "EU Union-wide", False, True))
    generator.add_function(EssentialFunction("FUNC-PAY-01", "Procesamiento de Pagos Bizum / Tarjetas", "Banca de Particulares", True, ["CTR-AWS-2024-01"], 2.0, 1.0, 0.25))
    return generator


def main() -> None:
    parser = argparse.ArgumentParser(description="Generador del Registro de Información DORA RoI.")
    parser.add_argument("--input-config", type=Path, help="Ruta al archivo JSON.")
    parser.add_argument("--output-dir", type=Path, default=Path("./dora_roi_reports"), help="Directorio de salida.")
    parser.add_argument("--generate-demo", action="store_true", help="Genera datos sintéticos demostrativos.")

    args = parser.parse_args()

    if not args.input_config and not args.generate_demo:
        parser.print_help()
        sys.exit(2)

    try:
        if args.generate_demo:
            generator = build_demo_generator()
        else:
            with open(args.input_config, encoding="utf-8") as f:
                data = json.load(f)
            generator = DORARoIGenerator(entity_name=data.get("entity_name", "Entidad"), entity_lei=data.get("entity_lei", "00000000000000000000"))
            for p in data.get("providers", []):
                generator.add_provider(ICTProvider(**p))
            for c in data.get("contracts", []):
                generator.add_contract(ICTContract(**c))
            for fn in data.get("functions", []):
                generator.add_function(EssentialFunction(**fn))

        out_json = args.output_dir / "dora_register_of_information.json"
        out_md = args.output_dir / "dora_register_of_information.md"
        generator.export_json(out_json)
        generator.export_markdown(out_md)
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Error generando RoI: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

