"""
Module: init_audit_structure.py
Description: Production-ready enterprise component for Init Audit Structure.
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
Module: init_audit_structure.py
Description: Production-ready enterprise component for Init Audit Structure.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import shutil
from pathlib import Path

def main():
    base_dir = Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS")
    
    levels = {
        "Nivel_1_Gobernanza": [
            "RGPD - LOPDGDD",
            "ENISA EU Cyber Act",
            "ENS 1-3-5"
        ],
        "Nivel_2_Operativo": [
            "NIS2",
            "NIST SP 800-53161",
            "OWASP top 10",
            "OWASP LLM",
            "EU IA Act",
            "Supply Chain Security"
        ],
        "Nivel_3_Exigencia_Tecnica": [
            "DORA",
            "FIPS 140-3 - 186-5 - 197-202",
            "PQC FIPS 203-204-205",
            "IP  PE Hardening"
        ]
    }

    logger.info("[*] Iniciando estructuración de auditorías en 3 niveles...")

    for level_dir, source_dirs in levels.items():
        level_path = base_dir / level_dir
        level_path.mkdir(exist_ok=True)
        logger.info(f"\n[+] Creado directorio nivel: {level_path.name}")
        
        for src_dir in source_dirs:
            src_path = base_dir / src_dir
            if src_path.exists() and src_path.is_dir():
                # Destination inside the level folder
                dest_path = level_path / src_dir
                
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                
                shutil.copytree(src_path, dest_path)
                logger.info(f"  -> Copiado: {src_dir}")
            else:
                logger.info(f"  [!] Advertencia: Directorio origen no encontrado: {src_dir}")

    logger.info("\n[*] Migración e inicialización completada con éxito.")

if __name__ == "__main__":
    main()
