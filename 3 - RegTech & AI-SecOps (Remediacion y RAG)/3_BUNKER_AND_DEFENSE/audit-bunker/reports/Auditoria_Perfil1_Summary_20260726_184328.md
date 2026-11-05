# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 1 (PRODUCCIÓN REAL)

- **Fecha (ISO-8601):** `2026-07-26T18:43:28.764491+00:00`
- **Modo de Ejecución:** `PRODUCCIÓN REAL (NO DRY-RUN)`
- **Duración Total:** `3.87s`
- **Firma SHA-256:** `67F19B463D2E2085528C1F2B1E051AA8935FF522D0B6977AF1032090A4D3A187`

## Resultados por Fase

| Fase | Normativa | Script | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | Supply Chain | generate_sbom.py | **PASSED** | 1.06s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 02 | RGPD / LOPDGDD | rgpd_data_pseudonymizer.ps1 | **PASSED** | 2.26s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_pseudonymizer.ps1 -SourceDB E:\PROYECTOS IA\AUDITORIAS\reports\audit_database.db -Mode Pseudonymize -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 03 | OWASP Top 10 | ast_scan.py | **PASSED** | 0.14s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP top 10\ast_scan.py --path E:\PROYECTOS IA\TODO BUNKER_OS\no_software` |
| 04 | OWASP LLM | llm_prompt_guard.py | **PASSED** | 0.15s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP LLM\llm_prompt_guard.py --prompt Evaluación de seguridad de prompt para Perfil 1 (PROD) --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 05 | RGPD / LOPDGDD | sar_data_extractor.py | **PASSED** | 0.21s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\sar_data_extractor.py --subject-identifier audit_user@domain.local --target-db E:\PROYECTOS IA\AUDITORIAS\reports\audit_events.db --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 06 | RGPD / LOPDGDD | rgpd_data_retention_purger.py | **SKIPPED** | 0.0s | `NONE` |