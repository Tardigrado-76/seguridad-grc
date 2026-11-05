"""
Module: check_cisa_kev.py
Description: Production-ready enterprise component for Check Cisa Kev.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import os
import logging


logger = logging.getLogger(__name__)
"""
Module: check_cisa_kev.py
Description: Production-ready enterprise component for Check Cisa Kev.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import json
import urllib.request
import urllib.error
import re
import sys
import argparse
from pathlib import Path

# Configuracion y Constantes
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT = 10

def fetch_cisa_kev():
    logger.info(f"[*] Obteniendo feed CISA KEV de: {CISA_KEV_URL}")
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                return data.get('vulnerabilities', [])
    except urllib.error.URLError as e:
        logger.info(f"[!] Error de conexion al obtener CISA KEV: {e}")
    except Exception as e:
        logger.info(f"[!] Error inesperado: {e}")
    return []

def parse_requirements(requirements_path):
    req_file = Path(requirements_path)
    if not req_file.exists():
        logger.info(f"[!] Archivo {req_file} no encontrado.")
        return []
    
    deps = []
    try:
        with open(req_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        with open(req_file, 'r', encoding='utf-16') as f:
            lines = f.readlines()
        
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Simple regex para capturar nombre de paquete
        match = re.match(r'^([a-zA-Z0-9_\-]+)', line)
        if match:
            deps.append(match.group(1).lower())
    return deps

def analyze_supply_chain(requirements_path):
    logger.info("[*] Iniciando Análisis de Cadena de Suministro (CISA KEV)")
    logger.info(f"[*] Archivo auditado: {requirements_path}")
    
    vulns = fetch_cisa_kev()
    if not vulns:
        logger.info("[!] No se pudieron obtener vulnerabilidades. Abortando chequeo.")
        sys.exit(1)
        
    logger.info(f"[+] Cargadas {len(vulns)} vulnerabilidades conocidas explotadas.")
    
    deps = parse_requirements(requirements_path)
    if not deps:
        logger.info("[!] No se encontraron dependencias válidas para analizar.")
        sys.exit(0)
        
    logger.info(f"[+] Verificando {len(deps)} dependencias...")
    
    found_vulns = False
    for vuln in vulns:
        product = vuln.get('product', '').lower()
        vendor = vuln.get('vendorProject', '').lower()
        
        for dep in deps:
            # Busqueda simple: si el nombre del paquete coincide con el producto o vendedor reportado en KEV
            if dep in product or dep in vendor:
                found_vulns = True
                logger.info(f"\n[ALERTA CRÍTICA] Posible dependencia vulnerable detectada: {dep}")
                logger.info(f"    -> CVE: {vuln.get('cveID')}")
                logger.info(f"    -> Vulnerabilidad: {vuln.get('vulnerabilityName')}")
                logger.info(f"    -> Acción recomendada CISA: {vuln.get('action')}")
                logger.info(f"    -> Fecha de resolución requerida: {vuln.get('dueDate')}")
                
    if not found_vulns:
        logger.info("[+] Análisis Completado: No se encontraron coincidencias con el catálogo KEV de CISA.")
        sys.exit(0)
    else:
        logger.info("\n[!] Análisis Fallido: Existen dependencias bajo riesgo activo. Por favor, revíselas inmediatamente.")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auditor independiente de dependencias contra el catálogo CISA KEV.")
    parser.add_argument("-r", "--requirements", default="./requirements.txt", help="Ruta al archivo requirements.txt a auditar (por defecto: ./requirements.txt).")
    parser.add_argument("-p", "--project", help="Ruta al directorio del proyecto (si se proporciona, buscará requirements.txt en ese directorio).")
    
    args = parser.parse_args()
    
    req_path = args.requirements
    if args.project:
        req_path = os.path.join(args.project, "requirements.txt")
        
    analyze_supply_chain(req_path)
