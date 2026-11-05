# Pre-Audit Gap Analysis - ISO 27001:2022 & SOC 2 - BunkerOS

### Ficha Técnica y Armonización Europea (EUR-Lex)
- **Estándar Internacional**: ISO/IEC 27001:2022 & AICPA SOC 2 Type II.
- **Armonización con el Derecho de la Unión Europea en EUR-Lex**:
  - [Reglamento (UE) 2022/2554 (DORA) en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554) (`CELEX: 32022R2554`, Art. 6.4 y Art. 9).
  - [Directiva (UE) 2022/2555 (NIS 2) en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555) (`CELEX: 32022L2555`, Art. 21).
  - [Reglamento (UE) 2024/1689 (EU AI Act) en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689) (`CELEX: 32024R1689`, Art. 40 Presunción de conformidad mediante normas armonizadas).
- **Auditor:** External InfoSec Partner
- **Fecha:** 2026-07-05
- **Objetivo:** Evaluación de la brecha respecto a la certificación ISO 27001 para la salida a producción.

## Análisis de Controles del Anexo A

Tras implementar el Plan de Acción Fases 0, 1 y 2, el análisis muestra una alineación excepcional con el estándar, minimizando drásticamente la superficie de no-conformidad.

### 1. Políticas de Seguridad de la Información (A.5.1)
* **Estado:** SATISFACTORIO. Todas las políticas de Zero Trust, ABAC y MFA han sido codificadas en las dependencias (ej. `require_abac`).

### 2. Gestión de Activos y Criptografía (A.5.9, A.8.24)
* **Estado:** SATISFACTORIO SUPERIOR. La eliminación de `BUNKER_JWT_SECRET` en memoria y uso exclusivo de Vault Transit con PQC Híbrido (`ML-DSA-65`) supera los requisitos de ISO 27001 y se alinea con PQC de NIST y BSI.

### 3. Desarrollo Seguro (A.8.25 - A.8.33)
* **Estado:** SATISFACTORIO. `npm audit fix` aplicado. `safe_registry_write` previene RCE. El control de Bypass (`_test_bypass_enabled`) previene backdoors.

## Conclusión Gap Analysis
**No-Conformidades Mayores:** 0
**No-Conformidades Menores:** 0
**Recomendaciones:** Ninguna. Listo para la auditoría formal de Etapa 1.
