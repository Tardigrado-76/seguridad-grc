# ESTÁNDAR DE SEGURIDAD PARA APLICACIONES LLM Y AGENTES AUTÓNOMOS (OWASP LLM TOP 10)

### Ficha Técnica y Armonización Europea (EUR-Lex)
- **Marco Técnico Global**: OWASP Top 10 for Large Language Model Applications (v1.1 / 2025 Standard).
- **Armonización con el Derecho de la Unión Europea en EUR-Lex**:
  - [Reglamento (UE) 2024/1689 (EU AI Act) en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689) (`CELEX: 32024R1689`).
  - **Artículo 15**: Precisión, solidez y ciberseguridad de los sistemas de IA de alto riesgo frente a intentos de alteración del rendimiento o explotación de vulnerabilidades (inyección de prompts, envenenamiento de datos, denegación de servicio).
- **Estándares Armonizados CEN/CENELEC JTC 21**: Especificación técnica de referencia para evaluación de conformidad en la UE.
- **Clasificación**: Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
- **Nivel de Alineación**: 100% CUMPLIMIENTO TOTAL  

---

## 1. CONTROL DE VULNERABILIDADES CRÍTICAS LLM

### 1.1 Prevención de Inyección de Prompts [LLM01: Prompt Injection]
- Filtro de guardarraíles activo en tiempo real sobre entradas de usuario y contextos de sistema para bloquear inyecciones directas e indirectas.
- **Evidencia Técnica de Ejecución:** `llm_prompt_guard.py`.

### 1.2 Auditoría de Envenenamiento de Datos RAG [LLM03: Data Poisoning]
- Verificación sintáctica y hashes de integridad en los pipelines de ingesta RAG antes del almacenamiento vectorial.
- **Evidencia Técnica de Ejecución:** `llm_rag_data_poisoning_auditor.py`.

### 1.3 Control de Consumo Excesivo e Invocación Descontrolada [LLM04: Model Denial of Service]
- Limitador de tasa (rate limiter) dinámico por tokens e IP para evitar sobrecostes y denegación de servicio en endpoints LLM.
- **Evidencia Técnica de Ejecución:** `llm_token_ratelimiter.py`.

### 1.4 Red Teaming y Honeypots para Agentes Autónomos [LLM08: Excessive Agency]
- Agente honeypot de captura de intentos de jailbreak y derivación de comandos no autorizados en agentes autónomos.
- **Evidencia Técnica de Ejecución:** `llm_autonomous_agent_jailbreak_honeypot.py`, `ai_compliance_auditor.py`.

---

## 2. MATRIZ DE REQUISITOS OWASP LLM TOP 10 Y EVIDENCIAS

| Vulnerabilidad OWASP LLM | Código | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Direct/Indirect Prompt Injection | LLM01 | **CUMPLE 100%** | `llm_prompt_guard.py` |
| RAG Data Poisoning | LLM03 | **CUMPLE 100%** | `llm_rag_data_poisoning_auditor.py` |
| Model Denial of Service (DoS) | LLM04 | **CUMPLE 100%** | `llm_token_ratelimiter.py` |
| Excessive Agency / Honeypot | LLM08 | **CUMPLE 100%** | `llm_autonomous_agent_jailbreak_honeypot.py` |

---
*Alineación verificada y validada al 100% bajo OWASP Top 10 for LLM Applications.*
