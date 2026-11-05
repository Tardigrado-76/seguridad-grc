# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 3 (Grado Militar / PQC / DEMO)

- **Fecha (ISO-8601):** `2026-07-26T18:44:50.629066+00:00`
- **Modo de Ejecución:** `DEMO / SIMULACIÓN SEGURA`
- **Espacio de Trabajo (Workspace):** `E:\PROYECTOS IA\TODO BUNKER_OS\no_software`
- **Directorio de Informes:** `E:\PROYECTOS IA\AUDITORIAS\reports`
- **Duración Total:** `6.91s`
- **Firma Integridad SHA-256:** `D41A6993A806441A5BB5B8018C28FB2EB8A8530E83268234D0168FFDBEA76465`

## Matriz de Conformidad Legal y Técnica (Perfil 3)

| Fase | Marco Normativo | Script de Control | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | PQC (FIPS) | 11_collect-pqc-evidence.sh | **SKIPPED** | 0.0s | `NONE` |
| 02 | Supply Chain | generate_sbom.py | **PASSED** | 1.02s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 03 | Supply Chain / NIS2 | cisa_kev_gate.py | **FAILED** | 0.17s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\cisa_kev_gate.py --sbom E:\PROYECTOS IA\AUDITORIAS\reports\BunkerOS_SBOM_v1.json --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 04 | PQC (FIPS 203/204) | pqc_crypto_agility_manager.py | **SKIPPED** | 0.0s | `NONE` |
| 05 | FIPS 140-3 | fips_mode_enforcer.py | **SKIPPED** | 0.0s | `NONE` |
| 06 | ENS Nivel Alto | ens_fim_enforcer.ps1 | **FAILED** | 1.28s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\ENS 1-3-5\ens_fim_enforcer.ps1 -Mode ScanAndEnforce -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports -DryRun` |
| 07 | EU AI Act | ai_model_provenance_signer.py | **FAILED** | 0.1s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\EU IA Act\ai_model_provenance_signer.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 08 | EU AI Act | ai_compliance_auditor.py | **FAILED** | 0.11s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\EU IA Act\ai_compliance_auditor.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 09 | OWASP LLM | llm_autonomous_agent_jailbreak_honeypot.py | **PASSED** | 0.19s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP LLM\llm_autonomous_agent_jailbreak_honeypot.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 10 | EU AI Act | eu_ai_act_model_watermarker.py | **PASSED** | 0.19s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\EU IA Act\eu_ai_act_model_watermarker.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 11 | DORA / CRA | dora_chaos_resilience_tester.py | **FAILED** | 0.14s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\DORA\dora_chaos_resilience_tester.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 12 | DORA | dora_automated_failover_drill.py | **PASSED** | 0.18s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\DORA\dora_automated_failover_drill.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 13 | PQC (FIPS 204) | fips_204_mldsa_git_commit_signer.py | **PASSED** | 0.2s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\PQC FIPS 203-204-205\fips_204_mldsa_git_commit_signer.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports --dry-run` |
| 14 | Supply Chain | slsa_provenance_signer.sh | **FAILED** | 3.26s | `bash E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\slsa_provenance_signer.sh --dry-run` |