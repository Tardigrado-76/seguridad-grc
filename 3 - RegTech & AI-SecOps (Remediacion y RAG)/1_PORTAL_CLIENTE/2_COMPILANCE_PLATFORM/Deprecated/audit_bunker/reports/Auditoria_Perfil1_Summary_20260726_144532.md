# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 1 (DEMO)

- **Fecha (ISO-8601):** `2026-07-26T14:45:32.211355+00:00`
- **Modo de Ejecución:** `DEMO / SIMULACIÓN (DRY-RUN)`
- **Duración Total:** `14.39s`
- **Firma SHA-256:** `FF85521B818BE2C25B03240941AA5D85D15D85734D6A616408C9133EAF3DF877`

## Resultados por Fase

| Fase | Normativa | Script | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | Supply Chain | generate_sbom.py | **PASSED** | 0.8s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 02 | RGPD / LOPDGDD | rgpd_data_pseudonymizer.ps1 | **PASSED** | 1.86s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_pseudonymizer.ps1 -SourceDB E:\PROYECTOS IA\AUDITORIAS\reports\demo_database.db -Mode Pseudonymize -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports -DryRun` |
| 03 | OWASP Top 10 | ast_scan.py | **PASSED** | 0.69s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP top 10\ast_scan.py --path E:\PROYECTOS IA\AUDITORIAS` |
| 04 | OWASP LLM | llm_prompt_guard.py | **PASSED** | 0.09s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP LLM\llm_prompt_guard.py --prompt Evaluación de seguridad de prompt para Perfil 1 --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 05 | RGPD / LOPDGDD | sar_data_extractor.py | **PASSED** | 0.19s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\sar_data_extractor.py --subject-identifier audit_demo_user@domain.local --target-db E:\PROYECTOS IA\AUDITORIAS\reports\demo_audit.db --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 06 | RGPD / LOPDGDD | rgpd_data_retention_purger.py | **PASSED** | 0.18s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_retention_purger.py --target-db E:\PROYECTOS IA\AUDITORIAS\reports\demo_audit.db --mode audit --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |