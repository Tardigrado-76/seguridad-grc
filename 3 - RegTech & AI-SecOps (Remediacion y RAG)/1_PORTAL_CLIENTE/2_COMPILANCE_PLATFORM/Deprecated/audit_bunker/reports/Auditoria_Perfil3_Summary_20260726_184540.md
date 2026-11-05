# Informe Ejecutivo de Auditoría de Ciberseguridad — Perfil 3 (Grado Militar / PQC / PRODUCCIÓN REAL)

- **Fecha (ISO-8601):** `2026-07-26T18:45:40.668927+00:00`
- **Modo de Ejecución:** `PRODUCCIÓN REAL (NO DRY-RUN)`
- **Espacio de Trabajo (Workspace):** `E:\PROYECTOS IA\TODO BUNKER_OS\no_software`
- **Directorio de Informes:** `E:\PROYECTOS IA\AUDITORIAS\reports`
- **Duración Total:** `3.61s`
- **Firma Integridad SHA-256:** `068A2499A4BBE80340E5BBFCECA923180342F9E4FD06BA5C754A11A72938401F`

## Matriz de Conformidad Legal y Técnica (Perfil 3)

| Fase | Marco Normativo | Script de Control | Estado | Tiempo | Comando Ejecutado |
| :---: | :--- | :--- | :---: | :---: | :--- |
| 01 | PQC (FIPS) | 11_collect-pqc-evidence.sh | **SKIPPED** | 0.0s | `NONE` |
| 02 | Supply Chain | generate_sbom.py | **PASSED** | 0.97s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\generate_sbom.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 03 | Supply Chain / NIS2 | cisa_kev_gate.py | **FAILED** | 0.14s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\cisa_kev_gate.py --sbom E:\PROYECTOS IA\AUDITORIAS\reports\BunkerOS_SBOM_v1.json --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 04 | PQC (FIPS 203/204) | pqc_crypto_agility_manager.py | **SKIPPED** | 0.0s | `NONE` |
| 05 | FIPS 140-3 | fips_mode_enforcer.py | **SKIPPED** | 0.0s | `NONE` |
| 06 | ENS Nivel Alto | ens_fim_enforcer.ps1 | **FAILED** | 1.1s | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\ENS 1-3-5\ens_fim_enforcer.ps1 -Mode ScanAndEnforce -OutputDir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 07 | EU AI Act | ai_model_provenance_signer.py | **FAILED** | 0.1s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\EU IA Act\ai_model_provenance_signer.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 08 | EU AI Act | ai_compliance_auditor.py | **FAILED** | 0.09s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\EU IA Act\ai_compliance_auditor.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 09 | OWASP LLM | llm_autonomous_agent_jailbreak_honeypot.py | **PASSED** | 0.13s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\OWASP LLM\llm_autonomous_agent_jailbreak_honeypot.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 10 | EU AI Act | eu_ai_act_model_watermarker.py | **PASSED** | 0.12s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\EU IA Act\eu_ai_act_model_watermarker.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 11 | DORA / CRA | dora_chaos_resilience_tester.py | **FAILED** | 0.1s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\DORA\dora_chaos_resilience_tester.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 12 | DORA | dora_automated_failover_drill.py | **PASSED** | 0.14s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\DORA\dora_automated_failover_drill.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 13 | PQC (FIPS 204) | fips_204_mldsa_git_commit_signer.py | **PASSED** | 0.12s | `python E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\PQC FIPS 203-204-205\fips_204_mldsa_git_commit_signer.py --output-dir E:\PROYECTOS IA\AUDITORIAS\reports` |
| 14 | Supply Chain | slsa_provenance_signer.sh | **FAILED** | 0.53s | `bash E:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\Supply Chain Security\slsa_provenance_signer.sh` |