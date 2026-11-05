"""
Module: create_auditorias_final.py
Description: Production-ready enterprise component for Create Auditorias Final.
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
Module: create_auditorias_final.py
Description: Production-ready enterprise component for Create Auditorias Final.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import shutil
from pathlib import Path

def main():
    base_dir = Path(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS")
    final_dir = base_dir / "AUDITORIAS_FINAL"
    
    if final_dir.exists():
        shutil.rmtree(final_dir)
    final_dir.mkdir(parents=True)
    
    # Mapping of target directories to their required scripts
    # We will search the base_dir for these scripts and copy them over.
    
    ens_1_scripts = [
        "ens_access_policy_auditor.py",
        "ens_vulnerability_and_patch_auditor.py",
        "ENS_SOA_CATEGORIA_ALTA.md" # Reusing as base policy
    ]
    
    ens_2_scripts = ens_1_scripts + [
        "ens_fim_enforcer.ps1",
        "audit_final.ps1",
        "disa_stig_hardening.ps1",
        "init-secrets.ps1"
    ]
    
    ens_3_scripts = ens_2_scripts + [
        "tpm_fde_validator.ps1",
        "Bunker_secure_backup.py",
        "seal_and_backup.ps1",
        "bunker_backups_hardening.py"
    ]
    
    nis2_bajo_scripts = [
        "NIS2_POLITICA_SEGURIDAD_Y_INCIDENTES.md",
        "23_nca_incident_reporter.py",
        "ens_vulnerability_and_patch_auditor.py"
    ]
    
    nis2_medio_scripts = nis2_bajo_scripts + [
        "07_iam_privilege_auditor.py",
        "01_generate_sbom.py",
        "audit_final.ps1"
    ]
    
    nis2_alto_scripts = nis2_medio_scripts + [
        "NIST_SP800_53_161_ZERO_TRUST.md",
        "15_run_chaos_tests.ps1",
        "dora_chaos_resilience_tester.py",
        "supply_chain_dependency_checker.py"
    ]
    
    mapping = {
        "ENS 1": ens_1_scripts,
        "ENS 2": ens_2_scripts,
        "ENS 3": ens_3_scripts,
        "NIS2 bajo": nis2_bajo_scripts,
        "NIS2 medio": nis2_medio_scripts,
        "NIS2 alto": nis2_alto_scripts
    }
    
    # Pre-index all files to find them easily
    all_files = {}
    for root, dirs, files in os.walk(base_dir):
        if "AUDITORIAS_FINAL" in root:
            continue
        for file in files:
            # Prefer the original files over those in Nivel_X to avoid duplication issues
            if "Nivel_" not in root:
                all_files[file] = Path(root) / file
    
    for target_name, script_list in mapping.items():
        target_path = final_dir / target_name
        target_path.mkdir(exist_ok=True)
        logger.info(f"[*] Configurando {target_name}...")
        
        for script in script_list:
            if script in all_files:
                src = all_files[script]
                dst = target_path / script
                shutil.copy2(src, dst)
                logger.info(f"  -> Copiado: {script}")
            else:
                logger.info(f"  [!] No encontrado: {script}")
                
    logger.info("\n[+] Configuración de AUDITORIAS_FINAL completada.")

if __name__ == "__main__":
    main()
