# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 2 (Sector Público / DEMO)

- **Fecha (ISO-8601):** `2026-07-26T18:44:08.226706+00:00`
- **Modo de Ejecución:** `DEMO / SIMULACIÓN SEGURA`
- **Espacio de Trabajo (Workspace):** `E:\PROYECTOS IA\TODO BUNKER_OS\no_software`
- **Directorio de Informes:** `E:\PROYECTOS IA\AUDITORIAS\reports`
- **Duración Total:** `4.72s`
- **Firma Integridad SHA-256:** `0D81676D6919145D111937672CD8810DB0E3CDDCEBF7274B5F25DA759B6F71DC`

## Matriz de Conformidad Legal y Técnica (Perfil 2)

| Fase | Marco Normativo | Script de Control | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | Supply Chain / NIS2 | generate_sbom.py | **PASSED** | 1.32s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 02 | NIS2 | cisa_kev_gate.py | **FAILED** | 0.15s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\cisa_kev_gate.py --sbom E:\PROYECTOS IA\AUDITORIAS\reports\BunkerOS_SBOM_v1.json --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 03 | NIS2 | trm_vendor_scanner.py | **FAILED** | 0.18s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\NIS2\trm_vendor_scanner.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 04 | ENS Nivel Alto | disa_stig_hardening.ps1 | **SKIPPED** | 0.0s | `NONE` |
| 05 | ENS Nivel Alto | tpm_fde_validator.ps1 | **FAILED** | 1.33s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\ENS 1-3-5\tpm_fde_validator.ps1 -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports -DryRun` |
| 06 | ENS Nivel Alto | ens_fim_enforcer.ps1 | **FAILED** | 1.18s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\ENS 1-3-5\ens_fim_enforcer.ps1 -Mode ScanAndEnforce -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports -DryRun` |
| 07 | EU AI Act | ai_sec_guard.py | **FAILED** | 0.11s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\EU IA Act\ai_sec_guard.py --prompt Evaluación de seguridad AI Act Perfil 2 --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 08 | ENS / DORA | Bunker_secure_backup.py | **FAILED** | 0.16s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\ENS 1-3-5\Bunker_secure_backup.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 09 | DORA | dora_chaos_resilience_tester.py | **FAILED** | 0.11s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\DORA\dora_chaos_resilience_tester.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 10 | NIS2 | 23_nca_incident_reporter.py | **FAILED** | 0.13s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\NIS2\23_nca_incident_reporter.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |