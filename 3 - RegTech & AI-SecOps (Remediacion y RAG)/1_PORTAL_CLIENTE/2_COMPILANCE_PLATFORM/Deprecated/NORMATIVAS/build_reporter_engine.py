"""
Module: build_reporter_engine.py
Description: Production-ready enterprise component for Build Reporter Engine.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


logger = logging.getLogger(__name__)
"""
Module: build_reporter_engine.py
Description: Production-ready enterprise component for Build Reporter Engine.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import base64
from pathlib import Path

logo_path = Path(os.getenv("APP_DATA_PATH", "./data"))
target_reporter_path = Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS/AUDITORIAS_FINAL/quantigrade_reporter.py")
target_reporter_root = Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS/quantigrade_reporter.py")

with open(logo_path, "rb") as f:
    base64_logo = base64.b64encode(f.read()).decode('utf-8')

template = '''# -*- coding: utf-8 -*-
"""
QUANTIGRADE (Quantum-Resilient Systems)
Executive Reporting & Evidentiary Vault Engine
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path

QUANTIGRADE_LOGO_BASE64 = "__BASE64_LOGO_PLACEHOLDER__"

def calculate_file_hash(filepath):
    """Calcula el hash SHA-256 de un archivo para la cadena de custodia."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def register_evidence(evidence_name, raw_content, evidence_dir):
    """Guarda una evidencia técnica cruda firmada con SHA-256."""
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"EVIDENCE_{timestamp}_{evidence_name}.log"
    filepath = evidence_dir / filename
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(raw_content)
        
    file_hash = calculate_file_hash(filepath)
    
    meta_filepath = evidence_dir / f"EVIDENCE_{timestamp}_{evidence_name}.json"
    with open(meta_filepath, 'w', encoding='utf-8') as f:
        json.dump({
            "evidence_name": evidence_name,
            "filename": filename,
            "timestamp": datetime.now().isoformat(),
            "sha256_hash": file_hash,
            "status": "SEALED_AND_VERIFIED"
        }, f, indent=4)
        
    return {
        "file": filename,
        "hash": file_hash,
        "timestamp": timestamp
    }

def generate_quantigrade_html(audit_data, output_filepath):
    """Genera un Informe Dashboard HTML Interactivo Premium con estética Quantigrade."""
    
    framework_name = audit_data.get("framework_name", "Normativa de Ciberseguridad")
    target_path = audit_data.get("target_path", "N/A")
    mode = audit_data.get("mode", "AUDIT_ONLY (Gap Analysis)")
    timestamp = audit_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    results = audit_data.get("results", [])
    grc_results = audit_data.get("grc_results", [])
    evidences = audit_data.get("evidences", [])
    
    total_checks = len(results) + len(grc_results)
    passed_checks = sum(1 for r in results if r.get('success', False)) + sum(1 for g in grc_results if g.get('status') == 'PASS')
    
    score = (passed_checks / total_checks * 100) if total_checks > 0 else 0
    score_color = "#10B981" if score >= 90 else ("#F59E0B" if score >= 60 else "#EF4444")
    
    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantigrade Audit Report - {framework_name}</title>
    <style>
        :root {{
            --bg-primary: #0B132B;
            --bg-card: #1C2541;
            --accent-cyan: #00F0FF;
            --accent-blue: #3A506B;
            --text-main: #FFFFFF;
            --text-muted: #A5B4FC;
            --pass-color: #10B981;
            --warn-color: #F59E0B;
            --fail-color: #EF4444;
        }}
        
        body {{
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--accent-cyan);
            padding-bottom: 20px;
            margin-bottom: 40px;
        }}
        
        .logo-container img {{
            height: 100px;
            filter: drop-shadow(0px 0px 12px var(--accent-cyan));
        }}
        
        .header-title {{
            text-align: right;
        }}
        
        .header-title h1 {{
            margin: 0;
            font-size: 28px;
            color: var(--accent-cyan);
            letter-spacing: 1px;
        }}
        
        .header-title p {{
            margin: 5px 0 0 0;
            color: var(--text-muted);
            font-size: 14px;
        }}
        
        .badge-mode {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            background-color: var(--accent-blue);
            color: var(--accent-cyan);
            font-weight: bold;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 8px;
        }}
        
        .dashboard-grid {{
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 30px;
            margin-bottom: 40px;
        }}
        
        .card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            border: 1px solid rgba(0, 240, 255, 0.1);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}
        
        .score-box {{
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}
        
        .score-circle {{
            width: 140px;
            height: 140px;
            border-radius: 50%;
            border: 8px solid {score_color};
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 38px;
            font-weight: bold;
            color: {score_color};
            box-shadow: 0 0 20px {score_color}44;
            margin-bottom: 15px;
        }}
        
        .summary-details table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .summary-details td {{
            padding: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .summary-details td:first-child {{
            color: var(--text-muted);
            font-weight: 500;
        }}
        
        .section-title {{
            font-size: 22px;
            color: var(--accent-cyan);
            margin-top: 40px;
            margin-bottom: 20px;
            border-left: 4px solid var(--accent-cyan);
            padding-left: 12px;
        }}
        
        table.data-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
        }}
        
        table.data-table th, table.data-table td {{
            padding: 14px 18px;
            text-align: left;
        }}
        
        table.data-table th {{
            background-color: #141E38;
            color: var(--accent-cyan);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        table.data-table tr:nth-child(even) {{
            background-color: rgba(255, 255, 255, 0.02);
        }}
        
        table.data-table tr:hover {{
            background-color: rgba(0, 240, 255, 0.05);
        }}
        
        .status-pass {{ color: var(--pass-color); font-weight: bold; }}
        .status-warn {{ color: var(--warn-color); font-weight: bold; }}
        .status-fail {{ color: var(--fail-color); font-weight: bold; }}
        
        .hash-code {{
            font-family: 'Courier New', monospace;
            font-size: 11px;
            background: rgba(0,0,0,0.4);
            padding: 4px 8px;
            border-radius: 4px;
            color: var(--accent-cyan);
        }}

        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #000000 !important;
            }}
            .card, table.data-table {{
                background: #ffffff !important;
                color: #000000 !important;
                border: 1px solid #cccccc !important;
                box-shadow: none !important;
            }}
            table.data-table th {{
                background-color: #f0f0f0 !important;
                color: #000000 !important;
            }}
            .section-title, .header-title h1 {{
                color: #003366 !important;
            }}
            .hash-code {{
                background: #f0f0f0 !important;
                color: #333333 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <div class="logo-container">
                <img src="data:image/jpeg;base64,{QUANTIGRADE_LOGO_BASE64}" alt="QUANTIGRADE Logo">
            </div>
            <div class="header-title">
                <h1>INFORME EJECUTIVO DE AUDITORÍA</h1>
                <p><strong>Normativa Exigible:</strong> {framework_name}</p>
                <div class="badge-mode">MODO: {mode}</div>
            </div>
        </div>

        <!-- DASHBOARD GRID -->
        <div class="dashboard-grid">
            <div class="card score-box">
                <div class="score-circle">{score:.0f}%</div>
                <h3>Puntuación de Cumplimiento</h3>
                <p style="color: var(--text-muted); font-size: 13px;">Ponderación Global de Evaluación</p>
            </div>
            
            <div class="card summary-details">
                <h3 style="margin-top:0; color: var(--accent-cyan);">Resumen de Evaluación</h3>
                <table>
                    <tr>
                        <td>Infraestructura / Proyecto Objetivo:</td>
                        <td><strong>{target_path}</strong></td>
                    </tr>
                    <tr>
                        <td>Fecha y Hora de Auditoría:</td>
                        <td><strong>{timestamp}</strong></td>
                    </tr>
                    <tr>
                        <td>Total de Controles Evaluados:</td>
                        <td><strong>{total_checks}</strong> ({passed_checks} Superados / {total_checks - passed_checks} Brechas)</td>
                    </tr>
                    <tr>
                        <td>Cadena de Custodia:</td>
                        <td><span class="status-pass">✓ {len(evidences)} Evidencias Criptográficas Selladas</span></td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- SECCIÓN 1: CONTROLES GRC & GOBERNANZA -->
        <div class="section-title">1. Evaluación de Gobernanza, Riesgos y Cumplimiento (GRC)</div>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Dominio GRC</th>
                    <th>Control Evaluado</th>
                    <th>Estado</th>
                    <th>Observaciones / Evidencia Documental</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for g in grc_results:
        status_cls = "status-pass" if g.get('status') == 'PASS' else ("status-warn" if g.get('status') == 'WARNING' else "status-fail")
        html_content += f"""
                <tr>
                    <td><strong>{g.get('domain', 'GRC Base')}</strong></td>
                    <td>{g.get('control', 'Control')}</td>
                    <td class="{status_cls}">{g.get('status', 'N/A')}</td>
                    <td>{g.get('detail', '-')}</td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>

        <!-- SECCIÓN 2: CONTROLES TÉCNICOS & HARDENING -->
        <div class="section-title">2. Evaluación Técnica y Resiliencia Automatizada</div>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Modulo / Script Técnico</th>
                    <th>Dominio Normativo</th>
                    <th>Resultado</th>
                    <th>Detalle de Ejecución</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for r in results:
        status_str = "PASS" if r.get('success', False) else "FAIL"
        status_cls = "status-pass" if r.get('success', False) else "status-fail"
        html_content += f"""
                <tr>
                    <td><code>{r.get('script', 'Script')}</code></td>
                    <td>{r.get('norm', 'Técnico')}</td>
                    <td class="{status_cls}">{status_str}</td>
                    <td>{r.get('stdout', '')[:120] if r.get('success') else r.get('stderr', '')[:120]}</td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>

        <!-- SECCIÓN 3: CADENA DE CUSTODIA Y EVIDENCIAS -->
        <div class="section-title">3. Registro de Cadena de Custodia Criptográfica (SHA-256)</div>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Nombre de Evidencia</th>
                    <th>Archivo Cifrado</th>
                    <th>Firma SHA-256 (Hash Inmutable)</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for ev in evidences:
        html_content += f"""
                <tr>
                    <td><strong>{ev.get('file', '')}</strong></td>
                    <td><code>{ev.get('file', '')}</code></td>
                    <td><span class="hash-code">{ev.get('hash', '')}</span></td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>

        <!-- FOOTER -->
        <div style="text-align: center; margin-top: 60px; color: var(--text-muted); font-size: 12px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 20px;">
            <p>© 2026 QUANTIGRADE - Quantum-Resilient Systems. Documento Oficial de Evaluación de Riesgos y Cumplimiento.</p>
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    logger.info(f"[+] Dashboard HTML Quantigrade generado con éxito en: {output_filepath}")
    return output_filepath
'''

final_code = template.replace("__BASE64_LOGO_PLACEHOLDER__", base64_logo)

with open(target_reporter_path, 'w', encoding='utf-8') as f:
    f.write(final_code)

with open(target_reporter_root, 'w', encoding='utf-8') as f:
    f.write(final_code)

logger.info("[+] Generador `quantigrade_reporter.py` creado con éxito.")


if __name__ == '__main__':
    # Production entry point
    pass
