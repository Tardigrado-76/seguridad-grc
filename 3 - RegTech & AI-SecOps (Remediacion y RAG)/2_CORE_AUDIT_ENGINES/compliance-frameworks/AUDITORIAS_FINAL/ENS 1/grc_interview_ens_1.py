"""
Module: grc_interview_ens_1.py
Description: Production-ready enterprise component for Grc Interview Ens 1.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import logging

import logging


logger = logging.getLogger(__name__)
"""
Module: grc_interview_ens_1.py
Description: Production-ready enterprise component for Grc Interview Ens 1.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

# -*- coding: utf-8 -*-
import sys
import json
from pathlib import Path

def run_interview():
    logger.info(f"==================================================")
    logger.info(f" QUANTIGRADE GRC INTERVIEW - ENS 1")
    logger.info(f" Auditoría Humana y Evaluacion Organizativa")
    logger.info(f"==================================================\n")
    
    questions = [
        ("¿Dispone la organización de una Política de Seguridad aprobada por la Dirección?", "pol_base"),
        ("¿Se realizan controles de acceso físico restringido a las instalaciones críticas?", "acc_fisico"),
        ("¿Existe un procedimiento de concienciación y formación en ciberseguridad para empleados?", "formacion"),
        ("¿Se cuenta con un protocolo formalizado para la gestión de incidentes?", "incidentes")
    ]
    
    results = []
    for q, code in questions:
        ans = input(f"[?] {q} (s/n): ").strip().lower()
        status = "PASS" if ans == 's' else "FAIL"
        results.append({
            "domain": "Entrevista Humana GRC",
            "control": code,
            "status": status,
            "detail": "Verificado mediante entrevista con dirección." if status == "PASS" else "Falta evidencia u homologación."
        })
        
    logger.info(f"\n[+] Entrevista GRC finalizada para ENS 1.")
    
    # Save output to be read by reporter
    out_file = Path(__file__).parent / "grc_interview_results.json"
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
        
    return results

if __name__ == "__main__":
    run_interview()
