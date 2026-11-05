# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 1 (PRODUCCIÓN REAL)

- **Fecha (ISO-8601):** `2026-07-26T14:40:35.803316+00:00`
- **Modo de Ejecución:** `PRODUCCIÓN REAL (NO DRY-RUN)`
- **Duración Total:** `15.0s`
- **Firma SHA-256:** `2E017AAF788C1FDA09C323A226CD9C5C937C86A3453789EE3D142A891AEB239D`

## Resultados por Fase

| Fase | Normativa | Script | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | Supply Chain | generate_sbom.py | **PASSED** | 0.96s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 02 | RGPD / LOPDGDD | rgpd_data_pseudonymizer.ps1 | **FAILED** | 0.05s | `pwsh -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_pseudonymizer.ps1 -Mode Pseudonymize -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 03 | OWASP Top 10 | ast_scan.py | **FAILED** | 0.1s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP top 10\ast_scan.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 04 | OWASP LLM | llm_prompt_guard.py | **FAILED** | 0.11s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP LLM\llm_prompt_guard.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 05 | RGPD / LOPDGDD | sar_data_extractor.py | **FAILED** | 0.13s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\sar_data_extractor.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 06 | RGPD / LOPDGDD | rgpd_data_retention_purger.py | **FAILED** | 0.12s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_retention_purger.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |