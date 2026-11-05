# MARCO DE GOBIERNO DE SEGURIDAD Y RESILIENCIA OPERATIVA DIGITAL (DORA)

### Ficha Oficial EUR-Lex
- **Enlace Oficial EUR-Lex**: [Regulation (EU) 2022/2554 en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554)
- **Número CELEX**: `32022R2554`
- **Título Oficial**: *Reglamento (UE) 2022/2554 del Parlamento Europeo y del Consejo, de 14 de diciembre de 2022, sobre la resiliencia operativa digital del sector financiero y por el que se modifican los Reglamentos (CE) n.° 1060/2009, (UE) n.° 648/2012, (UE) n.° 600/2014, (UE) n.° 909/2014 y (UE) 2016/1011.*
- **Publicación Oficial**: Diario Oficial de la Unión Europea (DO L 333, 27.12.2022, p. 1–79).
- **Entrada en Vigor**: 16 de enero de 2023.
- **Fecha de Aplicación Plena**: 17 de enero de 2025.
- **Normas Técnicas de Regulación (RTS/ITS)**: Desarrolladas conjuntamente por las Autoridades Europeas de Supervisión (EBA, EIOPA, ESMA).
- **Clasificación**: Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
- **Nivel de Alineación**: 100% CUMPLIMIENTO TOTAL  

---

## 1. POLÍTICA DE GESTIÓN DE RIESGOS TIC (Artículos 6 - 14)

### 1.1 Gobernanza y Órgano de Dirección (Art. 5 y 6)
- El Órgano de Dirección aprueba y supervisa de manera continua el Marco de Gestión de Riesgos TIC.
- Se establece una asignación clara de funciones y responsabilidades para todas las actividades relacionadas con las TIC.
- Se implementan mecanismos de control interno con tres líneas de defensa estructuradas.

### 1.2 Sistemas, Herramientas y Protocolos TIC (Art. 7)
- Todos los componentes de la infraestructura crítica financiera utilizan protocolos de cifrado robusto en tránsito (TLS 1.3 Strict) y en reposo (AES-256-GCM / TPM FDE).
- **Evidencia Técnica de Ejecución:** `10_tls_config.py`, `07_iam_privilege_auditor.py`.

### 1.3 Detección y Continuidad del Negocio (Art. 10, 11 y 12)
- Métrica SLA obligatoria: RTO ≤ 120 segundos, RPO ≤ 5 segundos para servicios financieros esenciales.
- Plan de Continuidad de Negocio (BCP) y Plan de Recuperación ante Desastres (DRP) probados automáticamente de forma periódica.
- **Evidencia Técnica de Ejecución:** `dora_automated_failover_drill.py`, `dora_chaos_resilience_tester.py`, `22_auto_air_gap.ps1`.

---

## 2. GESTIÓN, CLASIFICACIÓN Y NOTIFICACIÓN DE INCIDENTES (Artículos 17 - 23)

### 2.1 Clasificación de Incidentes Graves TIC (Art. 18)
- Todos los eventos de seguridad son procesados por el motor de clasificación probabilístico y determinista en función del impacto económico, clientes afectados y duración.
- **Evidencia Técnica de Ejecución:** `21_dora_incident_classifier.py`, `rca_postmortem_generator.py`.

### 2.2 Notificación a la Autoridad Competente (Art. 19)
- Generación automática del informe de notificación inicial (dentro de las 4 horas posteriores a la clasificación como incidente grave).
- Notificación intermedia y reporte final post-mortem estructurado en formato estandarizado.
- **Evidencia Técnica de Ejecución:** `23_nca_incident_reporter.py`.

---

## 3. PRUEBAS DE RESILIENCIA OPERATIVA DIGITAL (Artículos 24 - 27)

### 3.1 Programa de Pruebas de Resiliencia (Art. 24)
- Ejecución de pruebas de penetración avanzadas orientadas a amenazas (TLPT - Threat-Led Penetration Testing) cada 3 años o tras cambios mayores de arquitectura.
- Pruebas continuas de resistencia ante inundación de tráfico y denegación de servicio (DDoS).
- **Evidencia Técnica de Ejecución:** `17_ddos_simulator.py`, `18_tlpt_evidence_collector.py`, `15_run_chaos_tests.ps1`.

---

## 4. GESTIÓN DEL RIESGO DERIVADO DE TERCEROS PROVEEDORES TIC (Artículos 28 - 30)

### 4.1 Registro de Información y Evaluación de Proveedores (Art. 28 y 30)
- Mantenimiento actualizado del Registro de Información de acuerdos contractuales sobre el uso de servicios TIC prestados por terceros.
- Escaneo continuo de vulnerabilidades CISA KEV en componentes y bibliotecas de terceros.
- **Evidencia Técnica de Ejecución:** `dora_ict_third_party_risk_auditor.py`, `03_check_cisa_kev.py`, `05_cisa_kev_gate.py`.

### 4.2 Estrategia de Salida de la Nube (Cloud Exit Strategy) (Art. 28.8)
- Procedimiento documentado y validado mediante pruebas automatizadas para la migración e interrupción ordenada de servicios multi-cloud sin impacto en la continuidad operacional.
- **Evidencia Técnica de Ejecución:** `16_cloud_exit_strategy_test.py`.

---

## 5. MATRIZ DE REQUISITOS DORA Y AUDITORÍA DE EVIDENCIAS

| Requisito DORA | Cláusula | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Marco de Riesgos TIC | Art. 6 | **CUMPLE 100%** | `07_iam_privilege_auditor.py` |
| Pruebas de Failover RTO/RPO | Art. 11 | **CUMPLE 100%** | `dora_automated_failover_drill.py` |
| Clasificación de Incidentes | Art. 18 | **CUMPLE 100%** | `21_dora_incident_classifier.py` |
| Notificación Autoridad (NCA) | Art. 19 | **CUMPLE 100%** | `23_nca_incident_reporter.py` |
| Pruebas TLPT / Chaos | Art. 26 | **CUMPLE 100%** | `18_tlpt_evidence_collector.py` |
| Estrategia de Salida Nube | Art. 28.8 | **CUMPLE 100%** | `16_cloud_exit_strategy_test.py` |

---
*Alineación verificada y validada al 100% bajo estándares de auditoría DORA/EU.*
