# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 1 (DEMO)

- **Fecha (ISO-8601):** `2026-07-26T18:41:27.672224+00:00`
- **Modo de Ejecución:** `DEMO / SIMULACIÓN (DRY-RUN)`
- **Directorio Analizado:** `E:\PROYECTOS IA\TODO BUNKER_OS\no_software`
- **Directorio de Informes:** `E:\PROYECTOS IA\AUDITORIAS\reports`
- **Duración Total:** `4.04s`
- **Firma SHA-256:** `FD07C7996DE44FA72C7E798991B7976DFE849A61BFBB4E4B98E75966E73040A8`

## Resultados por Fase

| Fase | Normativa | Script | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | Supply Chain | generate_sbom.py | **PASSED** | 1.19s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 02 | RGPD / LOPDGDD | rgpd_data_pseudonymizer.ps1 | **PASSED** | 2.09s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_pseudonymizer.ps1 -SourceDB E:\PROYECTOS IA\AUDITORIAS\reports\demo_database.db -Mode Pseudonymize -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports -DryRun` |
| 03 | OWASP Top 10 | ast_scan.py | **PASSED** | 0.28s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP top 10\ast_scan.py --path E:\PROYECTOS IA\TODO BUNKER_OS\no_software` |
| 04 | OWASP LLM | llm_prompt_guard.py | **PASSED** | 0.23s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP LLM\llm_prompt_guard.py --prompt Evaluación de seguridad de prompt para Perfil 1 --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 05 | RGPD / LOPDGDD | sar_data_extractor.py | **PASSED** | 0.21s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\sar_data_extractor.py --subject-identifier audit_demo_user@domain.local --target-db E:\PROYECTOS IA\AUDITORIAS\reports\demo_audit.db --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 06 | RGPD / LOPDGDD | rgpd_data_retention_purger.py | **SKIPPED** | 0.0s | `NONE` |