# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 2 (Sector Público / PRODUCCIÓN REAL)

- **Fecha (ISO-8601):** `2026-07-26T18:44:27.057207+00:00`
- **Modo de Ejecución:** `PRODUCCIÓN REAL (NO DRY-RUN)`
- **Espacio de Trabajo (Workspace):** `E:\PROYECTOS IA\TODO BUNKER_OS\no_software`
- **Directorio de Informes:** `E:\PROYECTOS IA\AUDITORIAS\reports`
- **Duración Total:** `4.78s`
- **Firma Integridad SHA-256:** `F099726CF5F374932062A21097C69C56AAFAA52030BDFFDBEFE49864259493B5`

## Matriz de Conformidad Legal y Técnica (Perfil 2)

| Fase | Marco Normativo | Script de Control | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | Supply Chain / NIS2 | generate_sbom.py | **PASSED** | 0.83s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 02 | NIS2 | cisa_kev_gate.py | **FAILED** | 0.17s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\cisa_kev_gate.py --sbom E:\PROYECTOS IA\AUDITORIAS\reports\BunkerOS_SBOM_v1.json --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 03 | NIS2 | trm_vendor_scanner.py | **FAILED** | 0.18s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\NIS2\trm_vendor_scanner.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 04 | ENS Nivel Alto | disa_stig_hardening.ps1 | **SKIPPED** | 0.0s | `NONE` |
| 05 | ENS Nivel Alto | tpm_fde_validator.ps1 | **FAILED** | 1.34s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\ENS 1-3-5\tpm_fde_validator.ps1 -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 06 | ENS Nivel Alto | ens_fim_enforcer.ps1 | **FAILED** | 1.49s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\ENS 1-3-5\ens_fim_enforcer.ps1 -Mode ScanAndEnforce -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 07 | EU AI Act | ai_sec_guard.py | **FAILED** | 0.12s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\EU IA Act\ai_sec_guard.py --prompt Evaluación de seguridad AI Act Perfil 2 (PROD) --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 08 | ENS / DORA | Bunker_secure_backup.py | **PASSED** | 0.36s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\ENS 1-3-5\Bunker_secure_backup.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 09 | DORA | dora_chaos_resilience_tester.py | **FAILED** | 0.12s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\DORA\dora_chaos_resilience_tester.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 10 | NIS2 | 23_nca_incident_reporter.py | **FAILED** | 0.13s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\NIS2\23_nca_incident_reporter.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |