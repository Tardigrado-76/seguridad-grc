# NOTIFICACIÓN TEMPRANA DE INCIDENTES NIS2 (24 HORAS)
**Dirigido a:** CSIRT Nacional / CCN-CERT (Sector Público) / INCIBE-CERT (Entidades Esenciales/Importantes)
**Normativa Aplicable:** Directiva (UE) 2022/2555 (NIS2) Art. 23 / ENS RD 311/2022

---

### 1. DATOS DE LA ENTIDAD NOTIFICANTE
- **Razón Social / Organismo:** Entidad del Sector Público / Infraestructura Crítica Regulada
- **Clasificación ENS:** Nivel Medio / Alto
- **Timestamp de Notificación:** `2026-07-28 11:33:33 UTC`
- **Operador Responsable:** `Tardigrado`
- **Entorno Evaluado:** `N16 (Windows)`

### 2. RESUMEN DE TELEMETRÍA Y EVALUACIÓN DE IMPACTO
| Módulo Táctico | Estado de Cumplimiento | Marco Normativo Asociado |
| :--- | :---: | :--- |
| Evaluación de Riesgos Terceros (SLSA L3+) | **SKIPPED** | CRA Art. 10 (Seguridad en Cadena de Suministro) | SLSA Level 3+ |
| Bloqueo Exploits Activos (CISA KEV Gate) | **SIMULATED** | NIS2 Art. 21(2)(e) (Gestión de Vulnerabilidades) | CISA KEV Catalog |
| Auditoría MFA y Cifrado (Art. 21) | **SKIPPED** | NIS2 Art. 21(2)(g) (MFA y Cifrado de Comunicaciones) | ENS [op.acc.4] |
| Control de Acceso ENS [op.acc.1] | **SIMULATED** | ENS RD 311/2022 [op.acc.1] (Control de Acceso) | NIS2 Art. 21(2)(i) |
| Cumplimiento Cloud EUCS | **SKIPPED** | ENISA EUCS (Esquema Europeo Certificación Cloud - Niveles Medio/Alto) |
| Reporte a Autoridades (CCN-CERT/INCIBE) | **SKIPPED** | NIS2 Art. 23 (Notificación Temprana 24h Incidentes a CCN-CERT / INCIBE) |
| Monitoreo Integridad de Archivos (FIM) | **SKIPPED** | ENS RD 311/2022 [op.exp.8] (Monitoreo Integridad FIM) | NIS2 Art. 21 |
| Agregador VEX Vulnerabilidades | **FAILED** | NIS2 Art. 21(2)(e) (VEX Aggregator) | CRA (Vulnerabilidades Cadena Suministro) |
| Auditoría Riesgos Proveedores IT (DORA/NIS2) | **SIMULATED** | DORA Art. 28-30 (Riesgo Proveedores IT) | NIS2 Art. 21(2)(d) |
| Transparencia y Marcas de Agua IA | **SKIPPED** | EU AI Act Art. 50 (Transparencia y Marcas de Agua IA Sector Público) |

### 3. PROTOCOLO DE RESPUESTA EN 24 HORAS (CONECTOR DE TELEMETRÍA)
- [x] **Alerta Temprana (24h):** Resumen de vulnerabilidades críticas y exploits activos (CISA KEV Gate).
- [x] **Evaluación Intermedia (72h):** Ingesta de IOCs y análisis de propagación en la cadena de suministro.
- [x] **Informe Final (1 mes):** Memoria completa de mitigación y cierre de brecha legal.

---
*Documento emitido oficialmente por la Suite Auditoría Sector Público & NIS2 (Perfil 2).*
