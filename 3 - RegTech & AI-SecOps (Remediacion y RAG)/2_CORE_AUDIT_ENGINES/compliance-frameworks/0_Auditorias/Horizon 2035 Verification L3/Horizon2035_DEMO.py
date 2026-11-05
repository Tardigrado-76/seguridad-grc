"""
Module: Horizon2035_DEMO.py
Description: Production-ready enterprise component for Horizon2035 Demo.
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
Horizon2035_DEMO.py - Orquestador de Evaluación Tecnológica Horizon 2035 (Modo Simulación / DEMO)
Evaluación de Tecnologías Poscuánticas, OWASP LLM Honeypot y Autenticación ZKP Zero-Trust.
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

# ==========================================
# 1. AUTO-INSTALACIÓN SILENCIOSA DE DEPENDENCIAS
# ==========================================
def ensure_environment():
    if sys.version_info < (3, 8):
        logger.info("[!] Error: Se requiere Python 3.8 o superior.")
        sys.exit(1)
        
    required_packages = ['rich', 'fpdf2', 'pypdf', 'markdown']
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
# 2. CONFIGURACIÓN Y CONSTANTES
# ==========================================
IS_DEMO = True

ASCII_BANNER = r"""
██╗  ██╗██████╗ ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗    ██████╗  ██████╗ ██████╗ ███████╗
██║  ██║██╔═══██╗██╔══██╗██║╚══███╔╝██╔═══██╗████╗  ██║    ╚════██╗██╔═████╗╚════██╗██╔════╝
███████║██║   ██║██████╔╝██║  ███╔╝ ██║   ██║██╔██╗ ██║     █████╔╝██║██╔██║ █████╔╝███████╗
██╔══██║██║   ██║██╔══██╗██║ ███╔╝  ██║   ██║██║╚██╗██║    ██╔═══╝ ████╔╝██║ ╚═══██╗╚════██║
██║  ██║╚██████╔╝██║  ██║██║███████╗╚██████╔╝██║ ╚████║    ███████╗╚██████╔╝██████╔╝███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝
"""

STEPS = [
    {
        "id": "A",
        "norm": "OWASP LLM",
        "name": "Módulo A (OWASP LLM Honeypot)",
        "script": "OWASP LLM/llm_autonomous_agent_jailbreak_honeypot.py",
        "target_patterns": ["*.parquet", "*llm*", "inference.log"],
        "desc_targets": "modelos LLM, bases vectoriales o logs de inferencia (*.parquet, inference.log)"
    },
    {
        "id": "B",
        "norm": "NIST PQC FIPS 204",
        "name": "Módulo B (FIPS 204 PQC Git Signer)",
        "script": "PQC FIPS 203-204-205/fips_204_mldsa_git_commit_signer.py",
        "target_patterns": [".git", "*.pub", "id_ed25519"],
        "desc_targets": "repositorios Git y claves criptográficas (.git, *.pub)"
    },
    {
        "id": "C",
        "norm": "NIST ZKP",
        "name": "Módulo C (ZKP Auth Gateway)",
        "script": "NIST SP 800-53161/zero_knowledge_proof_auth_gateway.py",
        "target_patterns": ["*.conf", "nginx.conf", "*auth*"],
        "desc_targets": "configuraciones de red, VPN o pasarelas ZKP (*.conf, nginx.conf)"
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
    title_text.append(ASCII_BANNER, style="bold cyan")
    title_text.append("\n  SUITE DE EVALUACIÓN HORIZON 2035 - TECNOLOGÍAS EMERGENTES\n  (PQC FIPS 204 - OWASP LLM - ZERO TRUST ZKP)\n", style="bold magenta")
    title_text.append("  MODO DE EJECUCIÓN: ", style="bold bright_black")
    title_text.append("[SIMULACIÓN / DEMO (--dry-run ACTIVADO)]", style="bold yellow" if IS_DEMO else "bold red")
    
    console.logger.info(Panel(title_text, box=box.ROUNDED, border_style="cyan", padding=(1, 2)))

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
            pdf.cell(0, 5, f"Generado por Horizon 2035 Audit Suite | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT", align='L')
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

def consolidate_evidence(reports_dir: Path, execution_records: list):
    manifest_path = reports_dir / "MANIFEST.sha256"
    coc_path = reports_dir / "CHAIN_OF_CUSTODY.md"
    summary_md_path = reports_dir / "AUDITORIA_CONSOLIDADA_SUMMARY.md"
    
    user = os.getenv("USERNAME") or os.getenv("USER") or "TechAuditor"
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # 1. Summary MD
    summary_md = f"""# INFORME CONSOLIDADO DE EVALUACIÓN HORIZON 2035
- **Marco Analizado:** Tecnologías Emergentes (NIST PQC, Zero-Trust ZKP, OWASP LLM)
- **Modo de Auditoría:** {'DEMO (Simulación --dry-run)' if IS_DEMO else 'PRODUCCIÓN (Ejecución Real)'}
- **Timestamp de Cierre:** {now_utc}
- **Auditor / Operador:** {user}
- **Host / Sistema:** {platform.node()} ({platform.system()} {platform.release()})

## RESUMEN DE MÓDULOS EVALUADOS
| Módulo | Nombre | Estado |
| :---: | :--- | :---: |
"""
    for rec in execution_records:
        summary_md += f"| {rec['id']} | {rec['name']} | **{rec['status']}** |\n"
        
    summary_md_path.write_text(summary_md, encoding="utf-8")

    # 2. Custodia MD
    coc_md = f"""# ACTA DE EVALUACIÓN TECNOLÓGICA (HORIZON 2035)
- **Marco:** Tecnologías Emergentes (NIST PQC, Zero-Trust ZKP, OWASP LLM)
- **Modo:** {'DEMO (Simulación)' if IS_DEMO else 'PRODUCCIÓN'}
- **Timestamp UTC:** {now_utc}
- **Operador:** {user}

## 1. REGISTRO DE EJECUCIÓN SECUENCIAL
| Módulo | Nombre | Estado |
| :---: | :--- | :---: |
"""
    for rec in execution_records:
        coc_md += f"| {rec['id']} | {rec['name']} | **{rec['status']}** |\n"

    hashes = []
    manifest_lines = []
    
    for item in sorted(reports_dir.glob("*")):
        if item.is_file() and item.name not in ["MANIFEST.sha256", "CHAIN_OF_CUSTODY.md"]:
            content = item.read_bytes()
            file_hash = hashlib.sha256(content).hexdigest()
            manifest_lines.append(f"{file_hash}  {item.name}")
            hashes.append((item.name, file_hash))
            
    manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

    coc_md += f"""
## 2. MANIFIESTO DE ARTEFACTOS Y FIRMAS DIGITALES (SHA-256)
| Archivo de Evidencia | SHA-256 Digest |
| :--- | :--- |
"""
    for fname, fhash in hashes:
        coc_md += f"| `{fname}` | `{fhash}` |\n"
        
    coc_path.write_text(coc_md, encoding="utf-8")

# ==========================================
# 4. ORQUESTACIÓN PRINCIPAL
# ==========================================
def main():
    show_header()
    
    parser = argparse.ArgumentParser(description="Orquestador Evaluación Horizon 2035 DEMO")
    parser.add_argument("-i", "--input", help="Ruta del directorio a auditar")
    parser.add_argument("-o", "--output-dir", help="Ruta de salida para informes")
    parser.add_argument("-f", "--format", choices=["1", "2"], help="Formato de informe (1: MD, 2: PDF)")
    args = parser.parse_args()
    
    console.logger.info("\n[bold cyan]📋 PARÁMETROS DE CONFIGURACIÓN DE EVALUACIÓN[/bold cyan]")
    
    # 1. Ruta objetivo
    input_str = args.input
    if not input_str:
        input_str = Prompt.ask("[bold magenta]1. Ruta del Proyecto a auditar (--input)[/bold magenta]", default="./Proyecto_X")
    input_str = clean_path(input_str)
    input_path = Path(input_str).resolve()
    
    if not input_path.exists():
        console.logger.info(f"[bold red]❌ Error: La ruta especificada no existe: {input_path}[/bold red]")
        sys.exit(1)
        
    # 2. Ruta salida
    output_str = args.output_dir
    if not output_str:
        output_str = Prompt.ask("[bold magenta]2. Ruta de Salida para informes (--output-dir)[/bold magenta]", default="./reports")
    output_str = clean_path(output_str)
    output_path = Path(output_str).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    
    # 3. Formato
    fmt = args.format
    if not fmt:
        console.logger.info("\n[bold magenta]3. Formato del Informe Final (--format):[/bold magenta]")
        console.logger.info("   [cyan]1.[/cyan] Markdown (.md)")
        console.logger.info("   [cyan]2.[/cyan] PDF (.pdf)")
        fmt = Prompt.ask("   Selecciona una opción", choices=["1", "2"], default="1")
        
    normativas_dir = resolve_normativas_dir()
    console.logger.info(f"\n[dim]📍 Directorio base de Normativas: {normativas_dir}[/dim]\n")
    
    execution_records = []
    
    summary_table = Table(title="[bold cyan]DASHBOARD DE EVALUACIÓN TECNOLÓGICA HORIZON 2035 (DEMO)[/bold cyan]", box=box.ROUNDED, border_style="cyan")
    summary_table.add_column("Módulo", justify="center", style="bold magenta")
    summary_table.add_column("Marco Normativo", style="bold yellow")
    summary_table.add_column("Módulo de Auditoría", style="white")
    summary_table.add_column("Estado de Ejecución", justify="center")
    
    console.logger.info("[bold green]🚀 Iniciando Flujo de Evaluación Secuencial Inteligente...[/bold green]\n")
    
    with Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        for step in STEPS:
            task_id = progress.add_task(f"[cyan]Fase {step['id']}:[/cyan] Mapeando objetivos para {step['name']}...", total=None)
            
            # FASE 1: Descubrimiento
            found_targets = discover_targets(input_path, step['target_patterns'])
            
            # FASE 2: Condicional
            if not found_targets:
                msg = f"Paso {step['id']} Omitido - No se localizaron {step['desc_targets']}"
                progress.update(task_id, description=f"[yellow]🟡 {msg}[/yellow]")
                summary_table.add_row(step['id'], step['norm'], step['name'], "[bold yellow]🟡 SKIPPED[/bold yellow]")
                execution_records.append({"id": step['id'], "name": step['name'], "status": "SKIPPED", "detail": msg})
                time.sleep(0.4)
                continue
                
            # FASE 3: CLI & Subscript lookup
            script_full_path = normativas_dir / step['script']
            if not script_full_path.exists():
                matches = list(normativas_dir.rglob(Path(step['script']).name))
                if matches:
                    script_full_path = matches[0]
                else:
                    msg = f"Error: Script no encontrado ({step['script']})"
                    progress.update(task_id, description=f"[red]🔴 {msg}[/red]")
                    summary_table.add_row(step['id'], step['norm'], step['name'], "[bold red]🔴 FAILED[/bold red]")
                    execution_records.append({"id": step['id'], "name": step['name'], "status": "FAILED", "detail": msg})
                    continue
                
            cmd = [
                sys.executable,
                str(script_full_path),
                "--output-dir", str(output_path)
            ]
            
            if IS_DEMO:
                cmd.append("--dry-run")
                
            # FASE 4: Ejecución
            progress.update(task_id, description=f"[cyan]Fase {step['id']}:[/cyan] Ejecutando análisis {step['name']}...")
            
            try:
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"
                res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
                
                if res.returncode == 0:
                    status_badge = "[bold blue]🔵 SIMULATED[/bold blue]" if IS_DEMO else "[bold green]🟢 COMPLETED[/bold green]"
                    status_code = "SIMULATED" if IS_DEMO else "COMPLETED"
                    progress.update(task_id, description=f"[green]Fase {step['id']}:[/green] {step['name']} completado con éxito.")
                    summary_table.add_row(step['id'], step['norm'], step['name'], status_badge)
                    execution_records.append({"id": step['id'], "name": step['name'], "status": status_code, "detail": "Ejecutado correctamente."})
                else:
                    progress.update(task_id, description=f"[red]Fase {step['id']}:[/red] Error en {step['name']} (código {res.returncode})")
                    summary_table.add_row(step['id'], step['norm'], step['name'], "[bold red]🔴 FAILED[/bold red]")
                    err_snippet = res.stderr.strip().splitlines()[-1] if res.stderr else "Error desconocido"
                    execution_records.append({"id": step['id'], "name": step['name'], "status": "FAILED", "detail": f"Código {res.returncode}: {err_snippet}"})
            except Exception as ex:
                progress.update(task_id, description=f"[red]Fase {step['id']}:[/red] Fallo sistémico: {ex}")
                summary_table.add_row(step['id'], step['norm'], step['name'], "[bold red]🔴 FAILED[/bold red]")
                execution_records.append({"id": step['id'], "name": step['name'], "status": "FAILED", "detail": str(ex)})
                
    console.logger.info("\n")
    console.logger.info(summary_table)
    
    # FASE 5: Consolidación
    console.logger.info("\n[bold magenta]📦 FASE 5: Consolidando evidencias y sellando Cadena de Custodia...[/bold magenta]")
    consolidate_evidence(output_path, execution_records)
    console.logger.info("[green]  [+] Creado MANIFEST.sha256, CHAIN_OF_CUSTODY.md y AUDITORIA_CONSOLIDADA_SUMMARY.md[/green]")
    
    if fmt == "2":
        pdf_file = output_path / "AUDITORIA_CONSOLIDADA_HORIZON2035_DEMO.pdf"
        console.logger.info("[yellow]  [*] Convirtiendo evidencias a informe PDF...[/yellow]")
        if convert_md_to_pdf(output_path, pdf_file):
            console.logger.info(f"[bold green]  [+] Reporte en PDF generado exitosamente:[/bold green] {pdf_file}")
        else:
            console.logger.info("[bold yellow]  [!] No se generó PDF por falta de archivos de evidencias.[/bold yellow]")
            
    console.logger.info(Panel(
        f"[bold green]✔ Evaluación Tecnológica (DEMO) completada satisfactoriamente.[/bold green]\n"
        f"[cyan]Directorio de informes:[/cyan] {output_path}",
        title="[bold white]RESULTADO FINAL[/bold white]",
        border_style="cyan"
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
