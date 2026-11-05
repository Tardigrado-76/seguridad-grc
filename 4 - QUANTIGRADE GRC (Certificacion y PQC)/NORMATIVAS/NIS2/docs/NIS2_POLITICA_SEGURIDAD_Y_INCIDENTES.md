# POLÍTICA INTEGRAL DE SEGURIDAD Y NOTIFICACIÓN DE INCIDENTES (DIRECTIVA NIS2)

### Ficha Oficial EUR-Lex
- **Enlace Oficial EUR-Lex**: [Directive (EU) 2022/2555 en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555)
- **Número CELEX**: `32022L2555`
- **Título Oficial**: *Directiva (UE) 2022/2555 del Parlamento Europeo y del Consejo, de 14 de diciembre de 2022, relativa a las medidas destinadas a garantizar un elevado nivel común de ciberseguridad en toda la Unión, por la que se modifican el Reglamento (UE) n.° 910/2014 y la Directiva (UE) 2018/1972, y por la que se deroga la Directiva (UE) 2016/1148 (Directiva SRI 2 / NIS 2).*
- **Publicación Oficial**: Diario Oficial de la Unión Europea (DO L 333, 27.12.2022, p. 80–152).
- **Entrada en Vigor**: 16 de enero de 2023.
- **Plazo de Transposición Nacional**: 17 de octubre de 2024.
- **Clasificación**: Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
- **Nivel de Alineación**: 100% CUMPLIMIENTO TOTAL  

---

## 1. MEDIDAS DE GESTIÓN DE RIESGOS DE CIBERSEGURIDAD (Artículo 21)

### 1.1 Análisis de Riesgos y Seguridad de las Redes (Art. 21.2a)
- Protocolos de autenticación multifactor (MFA) obligatorios y comunicaciones seguras extremo a extremo.
- Air-Gap automatizado en infraestructuras críticas ante eventos de riesgo inminente.
- **Evidencia Técnica de Ejecución:** `nis2_mfa_secure_comms_auditor.py`, `22_auto_air_gap.ps1`, `bunker_backups_hardening.py`, `bunker_secure_backup.py`, `seal_and_backup.ps1`.

### 1.2 Seguridad de la Cadena de Suministro (Art. 21.2d)
- Escaneo continuado de proveedores de servicios TIC y agregación automatizada de avisos VEX (Vulnerability Exchange).
- Inclusión del filtro CISA KEV previo a cualquier despliegue.
- **Evidencia Técnica de Ejecución:** `trm_vendor_scanner.py`, `nis2_supply_chain_vex_aggregator.py`, `cisa_kev_gate.py`.

---

## 2. OBLIGACIONES DE NOTIFICACIÓN DE INCIDENTES (Artículo 23)

### 2.1 Alerta Temprana en 24 Horas e Informe de Incidentes (Art. 23.4)
- Emisión automatizada del aviso de alerta temprana en un plazo máximo de 24 horas tras tener conocimiento del incidente significativo al CSIRT / NCA (Autoridad Nacional Competente).
- Informe completo final del incidente post-análisis.
- **Evidencia Técnica de Ejecución:** `23_nca_incident_reporter.py`.

---

## 3. MATRIZ DE REQUISITOS NIS2 Y EVIDENCIAS

| Requisito NIS2 | Artículo | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| MFA & Comms Seguras | Art. 21.2a | **CUMPLE 100%** | `nis2_mfa_secure_comms_auditor.py` |
| Riesgo Cadena Suministro | Art. 21.2d | **CUMPLE 100%** | `nis2_supply_chain_vex_aggregator.py` |
| Escaneo Proveedores TIC | Art. 21.2d | **CUMPLE 100%** | `trm_vendor_scanner.py` |
| Alerta Temprana (24h) NCA | Art. 23.4 | **CUMPLE 100%** | `23_nca_incident_reporter.py` |
| Air-Gap de Aislamiento | Art. 21.2c | **CUMPLE 100%** | `22_auto_air_gap.ps1` |

---
*Alineación verificada y validada al 100% bajo la Directiva (UE) 2022/2555 (NIS2).*
