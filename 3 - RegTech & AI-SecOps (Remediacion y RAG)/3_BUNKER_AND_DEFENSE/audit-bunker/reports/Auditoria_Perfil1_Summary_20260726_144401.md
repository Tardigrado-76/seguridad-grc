# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 1 (PRODUCCIÓN REAL)

- **Fecha (ISO-8601):** `2026-07-26T14:44:01.029169+00:00`
- **Modo de Ejecución:** `PRODUCCIÓN REAL (NO DRY-RUN)`
- **Duración Total:** `193.41s`
- **Firma SHA-256:** `D7F3A07B4098903BBE70A040A4F1259DEC6FF66B469C5CA3B5BF09054AAC1303`

## Resultados por Fase

| Fase | Normativa | Script | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | Supply Chain | generate_sbom.py | **PASSED** | 0.88s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 02 | RGPD / LOPDGDD | rgpd_data_pseudonymizer.ps1 | **FAILED** | 180.04s | `powershell -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_pseudonymizer.ps1 -Mode Pseudonymize -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 03 | OWASP Top 10 | ast_scan.py | **PASSED** | 0.59s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP top 10\ast_scan.py --path E:\PROYECTOS IA\AUDITORIAS` |
| 04 | OWASP LLM | llm_prompt_guard.py | **PASSED** | 0.11s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP LLM\llm_prompt_guard.py --prompt Evaluación de seguridad de prompt para Perfil 1 (PROD) --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 05 | RGPD / LOPDGDD | sar_data_extractor.py | **PASSED** | 0.14s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\sar_data_extractor.py --subject-identifier audit_user@domain.local --target-db E:\PROYECTOS IA\AUDITORIAS\reports\audit_events.db --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 06 | RGPD / LOPDGDD | rgpd_data_retention_purger.py | **PASSED** | 0.12s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\RGPD - LOPDGDD\rgpd_data_retention_purger.py --target-db E:\PROYECTOS IA\AUDITORIAS\reports\audit_events.db --mode audit --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |