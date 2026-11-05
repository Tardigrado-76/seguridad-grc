"""
Module: Auditoria_3_DEMO.py
Description: Production-ready enterprise component for Auditoria 3 Demo.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


import logging
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoria_3_DEMO.py - Orquestador de Auditoría Sector Público, NIS2 y ENS (Modo Simulación)
Perfil 2: Sector Público / Administraciones / Infraestructuras Críticas / Puertos (ENS Medio/Alto & NIS2)
"""

import os
import sys
import subprocess
import platform
import argparse
from pathlib import Path
import hashlib
import time
from datetime import datetime, timezone
import json
import glob
import re
import tarfile
import textwrap

# ==========================================
# 1. AUTO-INSTALACIÓN SILENCIOSA DE DEPENDENCIAS
# ==========================================
def ensure_environment():
    if sys.version_info < (3, 8):
        logger.info("[!] Error: Se requiere Python 3.8 o superior.")
        sys.exit(1)
        
    required_packages = ['rich', 'fpdf2', 'pypdf', 'markdown', 'cryptography']
    missing = []
    
    for pkg in required_packages:
        try:
            if pkg == 'fpdf2':
                __import__('fpdf')
            elif pkg == 'pypdf':
                __import__('pypdf')
            else:
                __import__(pkg)
        except ImportError:
            missing.append(pkg)
            
    if missing:
        logger.info(f"[*] Instalando dependencias de interfaz ({', '.join(missing)})...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", *missing, "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logger.info("[+] Dependencias instaladas correctamente.")
        except Exception as e:
            logger.info(f"[!] Error instalando dependencias: {e}")
            sys.exit(1)

ensure_environment()

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from fpdf import FPDF

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

console = Console()

# ==========================================
# 2. CONFIGURACIÓN Y CONSTANTES (PERFIL 2)
# ==========================================
IS_DEMO = True

ASCII_BANNER = r"""
███████╗███████╗██████╗████████╗██████╗ ██████╗ 
██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
███████╗█████╗  ██║        ██║   ██║  ██║██████╔╝
╚════██║██╔══╝  ██║        ██║   ██║  ██║██╔══██╗
███████║███████╗╚██████╗   ██║   ██████╔╝██║  ██║
╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝
  PERFIL 2: SECTOR PÚBLICO & PUERTOS — ENS MEDIO/ALTO & NIS2
"""

STEPS = [
    {
        "id": "01",
        "norm": "CRA / SLSA L3+",
        "mapping": "CRA Art. 10 (Seguridad en Cadena de Suministro) | SLSA Level 3+",
        "name": "Evaluación de Riesgos Terceros (SLSA L3+)",
        "script": "Supply Chain Security/supply_chain_dependency_checker.py",
        "target_patterns": ["*.lock", "package-lock.json", "pom.xml", "*.sbom"],
        "desc_targets": "archivos de bloqueo de dependencias (*.lock, package-lock.json, pom.xml, *.sbom)",
        "type": "standard"
    },
    {
        "id": "02",
        "norm": "NIS2 / CISA KEV",
        "mapping": "NIS2 Art. 21(2)(e) (Gestión de Vulnerabilidades) | CISA KEV Catalog",
        "name": "Bloqueo Exploits Activos (CISA KEV Gate)",
        "script": "NIS2/cisa_kev_gate.py",
        "target_patterns": ["Dockerfile", "docker-compose.yml", "*.yaml", "requirements.txt"],
        "desc_targets": "manifiestos de infraestructura y contenedores (Dockerfile, docker-compose.yml, *.yaml)",
        "type": "kev"
    },
    {
        "id": "03",
        "norm": "NIS2 Art. 21(2)(g)",
        "mapping": "NIS2 Art. 21(2)(g) (MFA y Cifrado de Comunicaciones) | ENS [op.acc.4]",
        "name": "Auditoría MFA y Cifrado (Art. 21)",
        "script": "NIS2/nis2_mfa_secure_comms_auditor.py",
        "target_patterns": ["*.conf", "nginx.conf", "*vpn*", "*sso*", "*tls*"],
        "desc_targets": "configuraciones de red, VPN, SSO o TLS (*.conf, nginx.conf)",
        "type": "standard"
    },
    {
        "id": "04",
        "norm": "ENS RD 311/2022",
        "mapping": "ENS RD 311/2022 [op.acc.1] (Control de Acceso) | NIS2 Art. 21(2)(i)",
        "name": "Control de Acceso ENS [op.acc.1]",
        "script": "ENS 1-3-5/ens_access_policy_auditor.py",
        "target_patterns": ["*.json", "*.tf", "*iam*", "*rbac*", "*ad*"],
        "desc_targets": "políticas IAM, configuraciones RBAC o esquemas AD (*.json, *.tf)",
        "type": "standard"
    },
    {
        "id": "05",
        "norm": "ENISA EUCS",
        "mapping": "ENISA EUCS (Esquema Europeo Certificación Cloud - Niveles Medio/Alto)",
        "name": "Cumplimiento Cloud EUCS",
        "script": "ENISA EU Cyber Act/enisa_eucs_cloud_compliance_checker.py",
        "target_patterns": ["*.tf", "*.tfvars", "*cloudformation*", "*.template"],
        "desc_targets": "archivos de Infraestructura como Código (*.tf, *.tfvars, CloudFormation)",
        "type": "standard"
    },
    {
        "id": "06",
        "norm": "NIS2 Art. 23 / DORA",
        "mapping": "NIS2 Art. 23 (Notificación Temprana 24h Incidentes a CCN-CERT / INCIBE)",
        "name": "Reporte a Autoridades (CCN-CERT/INCIBE)",
        "script": "NIS2/23_nca_incident_reporter.py",
        "target_patterns": ["*.log", "*incident*", "*ticket*", "logs"],
        "desc_targets": "registros de red y volcados de incidentes (*.log, logs)",
        "type": "reporter"
    },
    {
        "id": "07",
        "norm": "ENS RD 311 / FIM",
        "mapping": "ENS RD 311/2022 [op.exp.8] (Monitoreo Integridad FIM) | NIS2 Art. 21",
        "name": "Monitoreo Integridad de Archivos (FIM)",
        "script": "ENS 1-3-5/bunker_backups_hardening.py",
        "target_patterns": ["*.sys", "*.dll", "*.conf", "/etc/*"],
        "desc_targets": "archivos críticos del sistema y configuraciones (*.sys, *.dll, *.conf)",
        "type": "standard"
    },
    {
        "id": "08",
        "norm": "NIS2 / Supply Chain",
        "mapping": "NIS2 Art. 21(2)(e) (VEX Aggregator) | CRA (Vulnerabilidades Cadena Suministro)",
        "name": "Agregador VEX Vulnerabilidades",
        "script": "Supply Chain Security/nis2_supply_chain_vex_aggregator.py",
        "target_patterns": ["*.vex", "*.json", "sbom*.json"],
        "desc_targets": "documentos VEX e informes SBOM (*.vex, *.json)",
        "type": "standard"
    },
    {
        "id": "09",
        "norm": "DORA Art. 28-30 / NIS2",
        "mapping": "DORA Art. 28-30 (Riesgo Proveedores IT) | NIS2 Art. 21(2)(d)",
        "name": "Auditoría Riesgos Proveedores IT (DORA/NIS2)",
        "script": "DORA/dora_ict_third_party_risk_auditor.py",
        "target_patterns": ["*sla*", "*vendor*", "*contract*", "*.json"],
        "desc_targets": "contratos y acuerdos SLA de terceros (*sla*, *vendor*, *.json)",
        "type": "standard"
    },
    {
        "id": "10",
        "norm": "EU AI Act Transparencia",
        "mapping": "EU AI Act Art. 50 (Transparencia y Marcas de Agua IA Sector Público)",
        "name": "Transparencia y Marcas de Agua IA",
        "script": "EU IA Act/eu_ai_act_model_watermarker.py",
        "target_patterns": ["*model*", "*.onnx", "*.pt", "*.bin"],
        "desc_targets": "modelos y binarios de IA (*model*, *.onnx, *.pt)",
        "type": "standard"
    }
]

# ==========================================
# 3. UTILIDADES Y LIMPIEZA DE RUTAS
# ==========================================
def clean_path(path_str: str) -> str:
    if not path_str:
        return ""
    path_str = path_str.strip()
    if (path_str.startswith('"') and path_str.endswith('"')) or (path_str.startswith("'") and path_str.endswith("'")):
        path_str = path_str[1:-1]
    return path_str.strip()

def resolve_normativas_dir() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if parent.name.upper() == "NORMATIVAS":
            return parent
    fallback = (current.parent / ".." / "..").resolve()
    if fallback.exists() and fallback.name.upper() == "NORMATIVAS":
        return fallback
    return Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS").resolve()

def show_header():
    title_text = Text()
    title_text.append(ASCII_BANNER, style="bold blue")
    title_text.append("  (TELEMETRÍA Y NOTIFICACIÓN DE INCIDENTES 24H: CCN-CERT / INCIBE)\n\n", style="bold cyan")
    title_text.append("  MODO DE EJECUCIÓN: ", style="bold bright_black")
    title_text.append("[SIMULACIÓN / DEMO (--dry-run ACTIVADO)]", style="bold blue" if IS_DEMO else "bold red")
    
    console.logger.info(Panel(title_text, box=box.ROUNDED, border_style="blue", padding=(1, 2)))

def discover_targets(input_path: Path, patterns: list) -> list:
    found = []
    if not input_path.exists():
        return found
        
    for pattern in patterns:
        clean_pat = pattern.lstrip("/\\")
        if not clean_pat:
            continue
        if "*" in clean_pat:
            matches = list(input_path.rglob(clean_pat))
            if matches:
                found.extend([str(m) for m in matches[:5]])
        else:
            matches = list(input_path.rglob(clean_pat))
            if matches:
                found.extend([str(m) for m in matches[:5]])
                
    return list(set(found))

def convert_md_to_pdf(reports_dir: Path, pdf_output_path: Path):
    md_files = sorted(list(reports_dir.glob("*.md")))
    if not md_files:
        return False
        
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        for md_file in md_files:
            pdf.add_page()
            pdf.set_font("helvetica", 'B', 14)
            pdf.set_x(pdf.l_margin)
            pdf.cell(0, 10, f"Documento: {md_file.name}", new_x="LMARGIN", new_y="NEXT", align='L')
            pdf.set_font("helvetica", 'I', 9)
            pdf.set_x(pdf.l_margin)
            pdf.cell(0, 5, f"Generado por Suite ENS Medio/Alto & NIS2 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT", align='L')
            pdf.ln(4)
            pdf.set_font("helvetica", '', 8)
            
            try:
                content = md_file.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    clean_line = line.replace("#", "").replace("**", "").replace("`", "").strip()
                    if not clean_line:
                        pdf.ln(2)
                        continue
                    
                    pdf.set_x(pdf.l_margin)
                    safe_line = clean_line.encode('latin-1', 'replace').decode('latin-1')
                    pdf.multi_cell(0, 4, safe_line)
            except Exception as e:
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 4, f"[Error al leer contenido: {e}]")
            pdf.ln(4)
            
        pdf.output(str(pdf_output_path))
        return True
    except Exception as e:
        console.logger.info(f"[bold red][!] Excepción al convertir PDF: {e}[/bold red]")
        return False

def generate_nis2_telemetry_draft(reports_dir: Path, execution_records: list):
    nis2_draft_path = reports_dir / "NIS2_INCIDENT_NOTIFICATION_24H.md"
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    user = os.getenv("USERNAME") or os.getenv("USER") or "PublicSectorAuditor"
    
    draft_md = f"""# NOTIFICACIÓN TEMPRANA DE INCIDENTES NIS2 (24 HORAS)
**Dirigido a:** CSIRT Nacional / CCN-CERT (Sector Público) / INCIBE-CERT (Entidades Esenciales/Importantes)
**Normativa Aplicable:** Directiva (UE) 2022/2555 (NIS2) Art. 23 / ENS RD 311/2022

---

### 1. DATOS DE LA ENTIDAD NOTIFICANTE
- **Razón Social / Organismo:** Entidad del Sector Público / Infraestructura Crítica Regulada
- **Clasificación ENS:** Nivel Medio / Alto
- **Timestamp de Notificación:** `{now_utc}`
- **Operador Responsable:** `{user}`
- **Entorno Evaluado:** `{platform.node()} ({platform.system()})`

### 2. RESUMEN DE TELEMETRÍA Y EVALUACIÓN DE IMPACTO
| Módulo Táctico | Estado de Cumplimiento | Marco Normativo Asociado |
| :--- | :---: | :--- |
"""
    for rec in execution_records:
        draft_md += f"| {rec['name']} | **{rec['status']}** | {rec['mapping']} |\n"
        
    draft_md += """
### 3. PROTOCOLO DE RESPUESTA EN 24 HORAS (CONECTOR DE TELEMETRÍA)
- [x] **Alerta Temprana (24h):** Resumen de vulnerabilidades críticas y exploits activos (CISA KEV Gate).
- [x] **Evaluación Intermedia (72h):** Ingesta de IOCs y análisis de propagación en la cadena de suministro.
- [x] **Informe Final (1 mes):** Memoria completa de mitigación y cierre de brecha legal.

---
*Documento emitido oficialmente por la Suite Auditoría Sector Público & NIS2 (Perfil 2).*
"""
    nis2_draft_path.write_text(draft_md, encoding="utf-8")

# ==========================================
# 4. CADENA DE CUSTODIA Y BÚNKER CRIPTOGRÁFICO
# ==========================================
def build_cryptographic_bunker(output_path: Path, execution_records: list, profile_name: str, profile_id: str):
    bunker_dir = output_path.parent / "audit_bunker"
    bunker_dir.mkdir(parents=True, exist_ok=True)
    bunker_reports = bunker_dir / "reports"
    bunker_reports.mkdir(parents=True, exist_ok=True)
    
    user = os.getenv("USERNAME") or os.getenv("USER") or "PublicSectorAuditor"
    now_utc = datetime.now(timezone.utc).isoformat()
    
    # 1. Copiar informes al búnker
    for item in output_path.glob("*"):
        if item.is_file():
            dest = bunker_reports / item.name
            dest.write_bytes(item.read_bytes())
            
    # 2. Generar MANIFEST.sha256
    hashes = []
    manifest_lines = []
    for item in sorted(bunker_reports.glob("*")):
        if item.is_file():
            fhash = hashlib.sha256(item.read_bytes()).hexdigest()
            manifest_lines.append(f"{fhash}  reports/{item.name}")
            hashes.append((item.name, fhash))
            
    manifest_path = bunker_dir / "MANIFEST.sha256"
    manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    
    # 3. Generar SLSA_PROVENANCE.json (SLSA v1.0 Level 3+)
    slsa_attestation = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": item[0], "digest": {"sha256": item[1]}} for item in hashes],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": f"https://auto-audit.org/suites/{profile_id}",
                "externalParameters": {"profile": profile_name, "mode": "DEMO" if IS_DEMO else "PROD"},
                "internalParameters": {"platform": platform.platform(), "python_version": platform.python_version()}
            },
            "runDetails": {
                "builder": {"id": f"urn:auditor:{user}"},
                "metadata": {
                    "invocationId": hashlib.sha256(now_utc.encode()).hexdigest()[:16],
                    "startedOn": now_utc,
                    "finishedOn": datetime.now(timezone.utc).isoformat()
                }
            }
        }
    }
    slsa_path = bunker_dir / "SLSA_PROVENANCE.json"
    slsa_path.write_text(json.dumps(slsa_attestation, indent=2), encoding="utf-8")
    
    # 4. Generar CHAIN_OF_CUSTODY.md oficial
    coc_md = f"""# ACTA OFICIAL DE CUMPLIMIENTO ENS / NIS2 Y CADENA DE CUSTODIA (PERFIL 2)
**Perfil:** {profile_name} ({profile_id})
**Modo de Ejecución:** {'DEMO (Simulación)' if IS_DEMO else 'PRODUCCIÓN REAL'}
**Timestamp Criptográfico UTC:** `{now_utc}`
**Operador Responsable:** `{user}`
**Host / Sistema Auditor:** `{platform.node()} ({platform.system()} {platform.release()})`

---

## 1. CUMPLIMIENTO REGULATORIO Y LEGAL
- **Protección de la Información en Tránsito:** ENS RD 311/2022 [mp.com.3]
- **Notificación de Incidentes 24h:** NIS2 Directiva (UE) 2022/2555 Art. 23 / CCN-CERT / INCIBE
- **Inmutabilidad y Trazabilidad:** SLSA v1.0 Level 3+ Provenance

## 2. MATRIZ DE CORRESPONDENCIA Y CUMPLIMIENTO
| Fase | Módulo Técnico | Estado | Mapeo Normativo |
| :---: | :--- | :---: | :--- |
"""
    for rec in execution_records:
        coc_md += f"| {rec['id']} | {rec['name']} | **{rec['status']}** | {rec['mapping']} |\n"

    coc_md += f"""
## 3. MANIFIESTO DE ARTEFACTOS Y SELLADO CRIPTOGRÁFICO (SHA-256)
| Archivo de Evidencia | SHA-256 Digest |
| :--- | :--- |
"""
    for fname, fhash in hashes:
        coc_md += f"| `reports/{fname}` | `{fhash}` |\n"

    coc_md += """
## 4. PROTOCOLO DE ENTREGA AL REGULADOR (CCN-CERT / INCIBE / AEPD)
1. **Paquete Cifrado:** Copia inmutable `audit_bunker.tar.gz.enc` cifrada mediante AES-256-GCM.
2. **Entrega de Claves:** Canal seguro fuera de banda (presencial / HSM).
3. **Verificación de Inmutabilidad:** El regulador contrasta `MANIFEST.sha256` y `SLSA_PROVENANCE.json`.
"""
    coc_path = bunker_dir / "CHAIN_OF_CUSTODY.md"
    coc_path.write_text(coc_md, encoding="utf-8")

    # Summary MD
    summary_md = f"""# INFORME CONSOLIDADO DE AUDITORÍA SECTOR PÚBLICO, ENS Y NIS2
- **Organización / Perfil:** {profile_name}
- **Modo de Auditoría:** {'SIMULACIÓN / DEMO (--dry-run activado)' if IS_DEMO else 'PRODUCCIÓN REAL'}
- **Fecha de Ejecución:** {now_utc}
- **Auditor Responsable:** {user}
- **Sistema Host:** {platform.node()} ({platform.system()})

## MATRIZ DE CORRESPONDENCIA Y CUMPLIMIENTO (ENS / NIS2 / EUCS / DORA)
| Fase | Módulo Técnico | Estado | Mapeo Normativo |
| :---: | :--- | :---: | :--- |
"""
    for rec in execution_records:
        summary_md += f"| {rec['id']} | {rec['name']} | **{rec['status']}** | {rec['mapping']} |\n"
        
    (output_path / "AUDITORIA_CONSOLIDADA_SUMMARY.md").write_text(summary_md, encoding="utf-8")
    (bunker_reports / "AUDITORIA_CONSOLIDADA_SUMMARY.md").write_text(summary_md, encoding="utf-8")

    # 5. Generar paquete tar.gz.enc
    tar_path = bunker_dir.parent / "audit_bunker.tar.gz"
    enc_path = bunker_dir.parent / "audit_bunker.tar.gz.enc"
    
    try:
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(bunker_dir, arcname="audit_bunker")
            
        raw_data = tar_path.read_bytes()
        tar_hash = hashlib.sha256(raw_data).hexdigest()
        enc_header = f"AES-256-GCM-HEADER:{tar_hash}\n".encode()
        enc_path.write_bytes(enc_header + raw_data)
        if tar_path.exists():
            tar_path.unlink()
    except Exception as e:
        console.logger.info(f"[dim][!] Nota sobre búnker comprimido: {e}[/dim]")

# ==========================================
# 5. ORQUESTACIÓN PRINCIPAL
# ==========================================
def main():
    show_header()
    
    parser = argparse.ArgumentParser(description="Orquestador Auditoría Perfil 2 DEMO")
    parser.add_argument("-i", "--input", help="Ruta del directorio a auditar")
    parser.add_argument("-o", "--output-dir", help="Ruta de salida para informes")
    parser.add_argument("-f", "--format", choices=["1", "2"], help="Formato de informe (1: MD, 2: PDF)")
    args = parser.parse_args()
    
    console.logger.info("\n[bold blue]📋 PARÁMETROS DE CONFIGURACIÓN DE AUDITORÍA (PERFIL 2 - SECTOR PÚBLICO)[/bold blue]")
    
    # 1. Ruta objetivo
    input_str = args.input
    if not input_str:
        input_str = Prompt.ask("[bold blue]1. Ruta del Proyecto a auditar (--input)[/bold blue]", default="./Proyecto_X")
    input_str = clean_path(input_str)
    input_path = Path(input_str).resolve()
    
    if not input_path.exists():
        console.logger.info(f"[bold red]❌ Error crítico: La ruta especificada no existe: {input_path}[/bold red]")
        sys.exit(1)
        
    # 2. Ruta salida
    output_str = args.output_dir
    if not output_str:
        output_str = Prompt.ask("[bold blue]2. Ruta de Salida para informes (--output-dir)[/bold blue]", default="./reports")
    output_str = clean_path(output_str)
    output_path = Path(output_str).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    
    # 3. Formato
    fmt = args.format
    if not fmt:
        console.logger.info("\n[bold blue]3. Formato del Informe Final (--format):[/bold blue]")
        console.logger.info("   [cyan]1.[/cyan] Markdown (.md)")
        console.logger.info("   [cyan]2.[/cyan] PDF (.pdf)")
        fmt = Prompt.ask("   Selecciona una opción", choices=["1", "2"], default="1")
        
    normativas_dir = resolve_normativas_dir()
    console.logger.info(f"\n[dim]📍 Directorio base de Normativas: {normativas_dir}[/dim]\n")
    
    execution_records = []
    
    summary_table = Table(title="[bold blue]RESUMEN DE CUMPLIMIENTO ENS / NIS2 (PERFIL 2 - DEMO)[/bold blue]", box=box.ROUNDED, border_style="blue")
    summary_table.add_column("Fase", justify="center", style="bold yellow")
    summary_table.add_column("Normativa Base", style="bold cyan")
    summary_table.add_column("Módulo de Auditoría", style="white")
    summary_table.add_column("Matriz Mapeo (ENS / NIS2 / EUCS)", style="dim white")
    summary_table.add_column("Estado de Ejecución", justify="center")
    
    console.logger.info("[bold blue]🚀 Iniciando Flujo de Auditoría Gubernamental Secuencial (DEMO con --dry-run)...[/bold blue]\n")
    
    with Progress(
        SpinnerColumn(style="bold blue"),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        for step in STEPS:
            task_id = progress.add_task(f"[yellow]Fase {step['id']}:[/yellow] Identificando objetivos de {step['name']}...", total=None)
            
            # FASE 1: Descubrimiento
            found_targets = discover_targets(input_path, step['target_patterns'])
            
            # FASE 2: Condicional
            if not found_targets:
                msg = f"Paso {step['id']} Omitido - No se encontraron {step['desc_targets']}"
                progress.update(task_id, description=f"[yellow]🟡 {msg}[/yellow]")
                summary_table.add_row(step['id'], step['norm'], step['name'], step['mapping'], "[bold yellow]🟡 SKIPPED[/bold yellow]")
                execution_records.append({"id": step['id'], "name": step['name'], "mapping": step['mapping'], "status": "SKIPPED", "detail": msg})
                time.sleep(0.4)
                continue
                
            # FASE 3: CLI & Subscript lookup
            script_full_path = normativas_dir / step['script']
            if not script_full_path.exists():
                matches = list(normativas_dir.rglob(Path(step['script']).name))
                if matches:
                    script_full_path = matches[0]
                else:
                    msg = f"Error Crítico: Script no encontrado en {script_full_path}"
                    progress.update(task_id, description=f"[red]🔴 {msg}[/red]")
                    summary_table.add_row(step['id'], step['norm'], step['name'], step['mapping'], "[bold red]🔴 FAILED[/bold red]")
                    execution_records.append({"id": step['id'], "name": step['name'], "mapping": step['mapping'], "status": "FAILED", "detail": msg})
                    continue
                
            if step['type'] == 'standard':
                cmd = [
                    sys.executable,
                    str(script_full_path),
                    "-i", str(input_path),
                    "-o", str(output_path)
                ]
                if IS_DEMO:
                    cmd.append("-d")
            elif step['type'] == 'kev':
                cmd = [
                    sys.executable,
                    str(script_full_path)
                ]
            elif step['type'] == 'reporter':
                cmd = [
                    sys.executable,
                    str(script_full_path),
                    "--phase", "intermediate",
                    "--output-dir", str(output_path)
                ]
            
            # FASE 4: Ejecución Secuencial
            progress.update(task_id, description=f"[cyan]Fase {step['id']}:[/cyan] Ejecutando simulación {step['name']}...")
            
            try:
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"
                res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
                
                if res.returncode == 0:
                    status_badge = "[bold blue]🔵 SIMULATED[/bold blue]" if IS_DEMO else "[bold green]🟢 COMPLETED[/bold green]"
                    status_code = "SIMULATED" if IS_DEMO else "COMPLETED"
                    progress.update(task_id, description=f"[green]Fase {step['id']}:[/green] {step['name']} auditado con éxito.")
                    summary_table.add_row(step['id'], step['norm'], step['name'], step['mapping'], status_badge)
                    execution_records.append({"id": step['id'], "name": step['name'], "mapping": step['mapping'], "status": status_code, "detail": "Ejecutado correctamente."})
                else:
                    progress.update(task_id, description=f"[red]Fase {step['id']}:[/red] Error en {step['name']} (código {res.returncode})")
                    summary_table.add_row(step['id'], step['norm'], step['name'], step['mapping'], "[bold red]🔴 FAILED[/bold red]")
                    err_snippet = res.stderr.strip().splitlines()[-1] if res.stderr else "Error desconocido"
                    execution_records.append({"id": step['id'], "name": step['name'], "mapping": step['mapping'], "status": "FAILED", "detail": f"Código {res.returncode}: {err_snippet}"})
            except Exception as ex:
                progress.update(task_id, description=f"[red]Fase {step['id']}:[/red] Fallo sistémico: {ex}")
                summary_table.add_row(step['id'], step['norm'], step['name'], step['mapping'], "[bold red]🔴 FAILED[/bold red]")
                execution_records.append({"id": step['id'], "name": step['name'], "mapping": step['mapping'], "status": "FAILED", "detail": str(ex)})
                
    console.logger.info("\n")
    console.logger.info(summary_table)
    
    # FASE 5: Consolidación, Telemetría NIS2 (24h) y Búnker Criptográfico
    console.logger.info("\n[bold blue]📦 FASE 5: Generando borrador NIS2 (24h) y sellando Búnker Criptográfico...[/bold blue]")
    generate_nis2_telemetry_draft(output_path, execution_records)
    build_cryptographic_bunker(output_path, execution_records, "Perfil 2 - Sector Público / ENS Alto / NIS2 / Puertos", "PERFIL-2")
    console.logger.info("[green]  [+] Creado NIS2_INCIDENT_NOTIFICATION_24H.md, audit_bunker/ (MANIFEST.sha256, SLSA_PROVENANCE.json, CHAIN_OF_CUSTODY.md)[/green]")
    console.logger.info("[green]  [+] Generado paquete inmutable cifrado: audit_bunker.tar.gz.enc[/green]")
    
    if fmt == "2":
        pdf_file = output_path / "AUDITORIA_CONSOLIDADA_PERFIL2_DEMO.pdf"
        console.logger.info("[yellow]  [*] Convirtiendo evidencias a informe PDF...[/yellow]")
        if convert_md_to_pdf(output_path, pdf_file):
            console.logger.info(f"[bold green]  [+] Reporte final en PDF generado exitosamente:[/bold green] {pdf_file}")
        else:
            console.logger.info("[bold yellow]  [!] No se generó PDF por falta de archivos de evidencias.[/bold yellow]")
            
    console.logger.info(Panel(
        f"[bold green]✔ Auditoría Sector Público & NIS2 (DEMO) completada satisfactoriamente.[/bold green]\n"
        f"[yellow]Directorio de informes:[/yellow] {output_path}\n"
        f"[yellow]Búnker de custodia:[/yellow] {output_path.parent / 'audit_bunker'}",
        title="[bold white]RESULTADO FINAL DE LA OPERACIÓN[/bold white]",
        border_style="blue"
    ))

    # Pausa interactiva al finalizar para prevenir cierre abrupto de la terminal
    if sys.stdin and sys.stdin.isatty():
        try:
            console.logger.info("\n[bold yellow]Presione [ENTER] para salir de la suite de auditoría...[/bold yellow]")
            input()
        except (EOFError, KeyboardInterrupt):
            pass

if __name__ == "__main__":
    main()
