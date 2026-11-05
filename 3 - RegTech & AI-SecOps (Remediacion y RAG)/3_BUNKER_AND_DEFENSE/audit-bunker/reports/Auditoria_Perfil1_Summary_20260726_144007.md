# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 1 (DEMO)

- **Fecha (ISO-8601):** `2026-07-26T14:40:07.933848+00:00`
- **Modo de Ejecución:** `DEMO / SIMULACIÓN (DRY-RUN)`
- **Duración Total:** `22.39s`
- **Firma SHA-256:** `EFF31A72B13129E8834EBA157467B7719EC66660149EC7FA6D912F0A7CB91B40`

## Resultados por Fase

| Fase | Normativa | Script | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | Supply Chain | generate_sbom.py | **PASSED** | 8.25s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 02 | RGPD / LOPDGDD | rgpd_data_pseudonymizer.ps1 | **FAILED** | 0.05s | `pwsh -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_pseudonymizer.ps1 -Mode Pseudonymize -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports -DryRun` |
| 03 | OWASP Top 10 | ast_scan.py | **FAILED** | 0.1s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP top 10\ast_scan.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 04 | OWASP LLM | llm_prompt_guard.py | **FAILED** | 0.12s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP LLM\llm_prompt_guard.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 05 | RGPD / LOPDGDD | sar_data_extractor.py | **FAILED** | 0.13s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\sar_data_extractor.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 06 | RGPD / LOPDGDD | rgpd_data_retention_purger.py | **FAILED** | 0.17s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_retention_purger.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |