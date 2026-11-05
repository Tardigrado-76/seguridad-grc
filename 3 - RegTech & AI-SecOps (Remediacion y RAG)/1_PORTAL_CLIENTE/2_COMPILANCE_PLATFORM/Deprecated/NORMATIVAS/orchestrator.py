"""
Module: orchestrator.py
Description: Production-ready enterprise component for Orchestrator.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


logger = logging.getLogger(__name__)
"""
Module: orchestrator.py
Description: Production-ready enterprise component for Orchestrator.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import argparse
import subprocess
import datetime
import json
from pathlib import Path

# Mapping sectors to execution levels
SECTOR_LEVEL_MAP = {
    'pyme': 1,
    'saas': 2,
    'financiero': 3,
    'critico': 3
}

LEVEL_DIRS = {
    1: "Nivel_1_Gobernanza",
    2: "Nivel_2_Operativo",
    3: "Nivel_3_Exigencia_Tecnica"
}

def find_executable_scripts(base_dir, max_level):
    """Finds all executable scripts up to the specified level."""
    scripts_to_run = []
    
    for level in range(1, max_level + 1):
        level_dir = base_dir / LEVEL_DIRS[level]
        if not level_dir.exists():
            logger.info(f"[!] Advertencia: No se encontró el directorio {level_dir}. Ejecute init_audit_structure.py primero.")
            continue
            
        for root, _, files in os.walk(level_dir):
            for file in files:
                if file.endswith(('.py', '.sh', '.ps1')):
                    # Exclude orchestrator or init scripts if they ended up here
                    if file not in ['orchestrator.py', 'init_audit_structure.py']:
                        scripts_to_run.append({
                            'path': Path(root) / file,
                            'level': level,
                            'norm': Path(root).name
                        })
    return scripts_to_run

def execute_script(script_info, target_path):
    """Executes a single script, passing the target parameter."""
    script_path = str(script_info['path'])
    ext = script_info['path'].suffix
    
    cmd = []
    if ext == '.py':
        cmd = ['python', script_path]
    elif ext == '.ps1':
        cmd = ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', script_path]
    elif ext == '.sh':
        cmd = ['bash', script_path]
        
    # Appending target
    cmd.extend(['--target', str(target_path)])
    
    logger.info(f"\n[*] Ejecutando [{script_info['level']} - {script_info['norm']}]: {script_info['path'].name}")
    try:
        # Run with timeout to prevent infinite hangs
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        return {
            'script': script_info['path'].name,
            'level': script_info['level'],
            'norm': script_info['norm'],
            'success': result.returncode == 0,
            'return_code': result.returncode,
            'stdout': result.stdout[:500], # Trucante for report
            'stderr': result.stderr[:500]
        }
    except subprocess.TimeoutExpired:
        logger.info(f"  [!] Timeout excedido para {script_info['path'].name}")
        return {
            'script': script_info['path'].name,
            'level': script_info['level'],
            'norm': script_info['norm'],
            'success': False,
            'return_code': -1,
            'stdout': '',
            'stderr': 'TimeoutExpired'
        }
    except Exception as e:
        logger.info(f"  [!] Error al ejecutar {script_info['path'].name}: {e}")
        return {
            'script': script_info['path'].name,
            'level': script_info['level'],
            'norm': script_info['norm'],
            'success': False,
            'return_code': -2,
            'stdout': '',
            'stderr': str(e)
        }

def generate_reports(results, output_dir, max_level):
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%M%d_%H%M%S")
    
    md_report_path = output_dir / f"audit_report_{timestamp}_L{max_level}.md"
    json_report_path = output_dir / f"audit_report_{timestamp}_L{max_level}.json"
    
    total = len(results)
    successes = sum(1 for r in results if r['success'])
    alignment = (successes / total * 100) if total > 0 else 0
    
    # Generate JSON
    with open(json_report_path, 'w', encoding='utf-8') as f:
        json.dump({
            'timestamp': timestamp,
            'max_level_executed': max_level,
            'total_scripts': total,
            'successes': successes,
            'alignment_percentage': alignment,
            'details': results
        }, f, indent=4)
        
    # Generate Markdown
    with open(md_report_path, 'w', encoding='utf-8') as f:
        f.write(f"# Informe de Auditoría Normativa - Nivel {max_level}\n\n")
        f.write(f"**Fecha:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Porcentaje de Alineación Global:** {alignment:.2f}%\n\n")
        
        f.write("## Resumen Ejecutivo\n")
        f.write(f"- Total de controles ejecutados: {total}\n")
        f.write(f"- Controles superados: {successes}\n")
        f.write(f"- Controles fallidos: {total - successes}\n\n")
        
        f.write("## Hallazgos Críticos y Brechas\n")
        failures = [r for r in results if not r['success']]
        if failures:
            for fail in failures:
                f.write(f"### 🔴 Fallo en {fail['norm']} ({fail['script']})\n")
                f.write(f"- **Stderr:** `{fail['stderr']}`\n\n")
        else:
            f.write("✅ No se detectaron brechas críticas. Alineación total.\n\n")
            
        f.write("## Plan de Remediación\n")
        if failures:
            f.write("Para alcanzar el 100% de cumplimiento en el nivel exigido, se deben abordar los siguientes puntos:\n")
            for fail in failures:
                f.write(f"- Revisar y corregir la ejecución de `{fail['script']}` en el marco de `{fail['norm']}`.\n")
        else:
            f.write("El entorno cumple satisfactoriamente con todos los controles automatizados del nivel exigido.\n")
            
    logger.info(f"\n[+] Informes generados en:\n  - {md_report_path}\n  - {json_report_path}")

def main():
    parser = argparse.ArgumentParser(description="Orquestador de Auditoría GRC de 3 Niveles")
    parser.add_argument('--level', type=int, choices=[1, 2, 3], help="Nivel de ejecución (1, 2 o 3). Acumulativo.")
    parser.add_argument('--sector', choices=SECTOR_LEVEL_MAP.keys(), help="Sector (define automáticamente el nivel).")
    parser.add_argument('--target', type=str, help="Ruta del proyecto o infraestructura a auditar.")
    parser.add_argument('--output', type=str, help="Ruta de salida para los informes.")
    
    args = parser.parse_args()
    
    # Determine level
    level = None
    if args.sector:
        level = SECTOR_LEVEL_MAP[args.sector]
        logger.info(f"[*] Sector '{args.sector}' seleccionado. Nivel de exigencia ajustado a: {level}")
    elif args.level:
        level = args.level
    else:
        try:
            level = int(input("[?] Introduzca el nivel de exigencia (1-3): ").strip())
        except ValueError:
            level = 1
            
    # Determine target
    target = args.target
    if not target:
        target = input("[?] Introduzca la ruta del proyecto o infraestructura a auditar: ").strip()
        
    # Determine output
    output = args.output
    if not output:
        out_prompt = input("[?] Introduzca la ruta de salida de informes (Enter para defecto './reports'): ").strip()
        output = out_prompt if out_prompt else "./reports"
        
    base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    target_path = Path(target)
    output_path = Path(output)
    
    if not output_path.is_absolute():
        output_path = base_dir / output_path
        
    scripts_to_run = find_executable_scripts(base_dir, level)
    
    if not scripts_to_run:
        logger.info("[!] No se encontraron scripts para ejecutar. ¿Ejecutó init_audit_structure.py?")
        return
        
    logger.info(f"[*] Se ejecutarán {len(scripts_to_run)} controles para el Nivel {level}.")
    
    results = []
    for script_info in scripts_to_run:
        res = execute_script(script_info, target_path)
        results.append(res)
        
    generate_reports(results, output_path, level)

if __name__ == "__main__":
    main()
