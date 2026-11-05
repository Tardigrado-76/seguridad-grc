# QUANTIGRADE GCR Enterprise Suite — Product Requirements Document (PRD)

## 1. Executive Summary & Vision
QUANTIGRADE GCR (Governance, Compliance & Risk) es la plataforma enterprise para auditoría cuantitativa, certificación de resiliencia operativa y salvaguarda regulatoria automatizada conforme a los marcos vigentes de la Unión Europea y el Estado Español (CRA, DORA, NIS2, EU AI Act, ENS, RGPD, eIDAS 2.0, ISA-IEC 62443, Mandato PQC NIST FIPS 203/204). Opera de forma 100% nativa y desatendida bajo estándares de ejecución Air-Gap (Cero-Docker, Cero fuga de telemetría).

## 2. Architecture & Core Subsystems
- **Core Mesh**:
  - `core_mesh.operational.airgap_armor`: Centinela de contención de tráfico de red y telemetría saliente con sellado de integridad.
  - `core_mesh.business_execution.merkle_bunker`: Estructura criptográfica de árbol de Merkle para prueba inmutable de evidencias de auditoría.
  - `core_mesh.business_execution.financial_impact_quantifier`: Modelo de cálculo dinámico de penalizaciones y sanciones normativas máximas según facturación y gravedad.
  - `core_mesh.agentic.regulatory_war_game`: Motor de simulación y stress-testing adversarial ante inspecciones regulatorias.
  - `core_mesh.operational.evidence_spec_registry`: Registro formal de especificaciones y controles para 20 marcos regulatorios.
  - `core_mesh.i18n`: Soporte multilingüe determinista (ES, EN, FR, DE, IT).
- **Execution Surfaces**:
  - `quantigrade_cli.py`: Interfaz de línea de comandos agéntica nativa (HKUDS CLI-Anything Standard) con salidas JSON deterministas y modo REPL interactivo.
  - `app_quantigrade_gcr_master.py`: Portal y dashboard interactivo analítico sobre Streamlit.
  - Lanzadores Windows UTF-8: `EJECUTAR_QUANTIGRADE_CLI.bat`, `INICIAR_QUANTIGRADE_SUITE_SEGURA.bat`.

## 3. Normative Scope
1. Cyber Resilience Act (CRA) & SBOM Tracking
2. Data Act (UE 2023/2854)
3. Digital Operational Resilience Act (DORA)
4. Digital Services Act (DSA)
5. eIDAS 2.0 (Identidad y Firmas Cualificadas)
6. ENISA EUCS (Esquema Europeo de Certificación Cloud)
7. Esquema Nacional de Seguridad (ENS)
8. EU AI Act (Reglamento de Inteligencia Artificial de la UE)
9. AESIA (Gobernanza de IA en España)
10. ISA-IEC 62443 (Ciberseguridad OT/IoT)
11. ISO/IEC 27001 & SOC 2 Tipo II
12. Ley de Secretos Empresariales
13. Ley General de Telecomunicaciones (LGTel)
14. LSSI-CE (Comercio Electrónico y Cookies)
15. Mandato PQC NIST FIPS 203-204 (Criptografía Post-Cuántica ML-KEM/ML-DSA)
16. Directiva NIS2 (UE 2022/2555)
17. Estándares OTAN C3
18. OWASP LLM Top 10 2025
19. Ley de Protección de Infraestructuras Críticas (LPIC)
20. RGPD / LOPDGDD

## 4. Quality Standards & Verification Gates
- **Zero Static Violations**: 0 errores en `ruff check --no-cache` y compatibilidad de tipado con `mypy` sin flags restrictivos (`--follow-imports=silent` innecesario; verificación limpia de Core Mesh e informes editoriales PDF).
- **TDD Test Suite**: 100% de tests unitarios y de integración pasando con `pytest -p no:cacheprovider` sin warnings críticos.
- **Native Runtime**: Ejecución 100% libre de contenedores Docker, con dependencias locales de Python 3.11+.
- **Air-Gap Telemetry**: Auditoría estricta de llamadas salientes mediante `AirGapArmorSentinel`.

## 5. Status & Certification
- **Tier Compliance**: Production Ready Tier 70 - 100.
- **Victory Audit Remediation**: Finding 3 completamente resuelto. Mypy ejecuta con 0 errores en `quantigrade_cli.py` y `editorial_pdf_generator.py`. 3/3 tests unitarios superados y generación de PDF ejecutivo validada empíricamente (4,351 bytes).
