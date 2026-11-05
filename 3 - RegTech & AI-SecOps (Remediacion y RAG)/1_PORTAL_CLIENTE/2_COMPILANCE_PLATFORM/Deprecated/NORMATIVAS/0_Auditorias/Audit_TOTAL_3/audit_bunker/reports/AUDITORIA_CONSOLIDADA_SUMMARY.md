# INFORME CONSOLIDADO DE AUDITORÍA SECTOR PÚBLICO, ENS Y NIS2 (PROD)
- **Organización / Perfil:** Perfil 2 - Sector Público / ENS Alto / NIS2 / Puertos
- **Modo de Auditoría:** PRODUCCIÓN REAL
- **Fecha de Ejecución:** 2026-07-28T16:49:51.268156+00:00
- **Auditor Responsable:** Tardigrado
- **Sistema Host:** N16 (Windows)

## MATRIZ DE CORRESPONDENCIA Y CUMPLIMIENTO (ENS / NIS2 / EUCS / DORA)
| Fase | Módulo Técnico | Estado | Mapeo Normativo |
| :---: | :--- | :---: | :--- |
| 01 | Evaluación de Riesgos Terceros (SLSA L3+) | **SKIPPED** | CRA Art. 10 (Seguridad en Cadena de Suministro) | SLSA Level 3+ |
| 02 | Bloqueo Exploits Activos (CISA KEV Gate) | **SKIPPED** | NIS2 Art. 21(2)(e) (Gestión de Vulnerabilidades) | CISA KEV Catalog |
| 03 | Auditoría MFA y Cifrado (Art. 21) | **SKIPPED** | NIS2 Art. 21(2)(g) (MFA y Cifrado de Comunicaciones) | ENS [op.acc.4] |
| 04 | Control de Acceso ENS [op.acc.1] | **COMPLETED** | ENS RD 311/2022 [op.acc.1] (Control de Acceso) | NIS2 Art. 21(2)(i) |
| 05 | Cumplimiento Cloud EUCS | **COMPLETED** | ENISA EUCS (Esquema Europeo Certificación Cloud - Niveles Medio/Alto) |
| 06 | Reporte a Autoridades (CCN-CERT/INCIBE) | **SKIPPED** | NIS2 Art. 23 (Notificación Temprana 24h Incidentes a CCN-CERT / INCIBE) |
| 07 | Monitoreo Integridad de Archivos (FIM) | **COMPLETED** | ENS RD 311/2022 [op.exp.8] (Monitoreo Integridad FIM) | NIS2 Art. 21 |
| 08 | Agregador VEX Vulnerabilidades | **FAILED** | NIS2 Art. 21(2)(e) (VEX Aggregator) | CRA (Vulnerabilidades Cadena Suministro) |
| 09 | Auditoría Riesgos Proveedores IT (DORA/NIS2) | **COMPLETED** | DORA Art. 28-30 (Riesgo Proveedores IT) | NIS2 Art. 21(2)(d) |
| 10 | Transparencia y Marcas de Agua IA | **FAILED** | EU AI Act Art. 50 (Transparencia y Marcas de Agua IA Sector Público) |
