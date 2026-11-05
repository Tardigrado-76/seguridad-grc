# Evaluación de Clasificación de Incidente TIC (DORA Art. 18)

**ID del Incidente:** `INC-2026-8841`  
**Fecha de Evaluación:** 2026-07-25T14:17:05.375029+00:00  
**Resultado de Clasificación DORA:** 🔴 INCIDENTE TIC MAYOR (MAJOR ICT INCIDENT)  
**Notificación Obligatoria a ANC (Banco de España / CNMV):** ⚠️ OBLIGATORIA (Plazo: 2 horas)  

---

## 1. Resumen de la Evaluación

- **Servicio Afectado:** API Gateway Pagos (Función Esencial/Crítica: `True`)
- **Criterios DORA Activados:** 4 / 5
- **Reglamento Aplicable:** DORA (UE) 2022/2554 Art. 17-23 & EBA/RTS/2024/02

---

## 2. Desglose de Criterios y Umbrales Evaluados

| Criterio Evaluado | Referencia Reglamentaria | Estado | Valor Observado | Umbral Exigido | Justificación |
|-------------------|--------------------------|--------|-----------------|----------------|---------------|
| **Clientes y Usuarios Afectados** | DORA Art. 18(1)(a) / RTS Art. 1 | 🔴 DISPARADO | `120,000 (15.00%)` | >= 100,000 o >= 10.0% | El número de clientes afectados (120,000) o el porcentaje (15.00%) supera los umbrales de impacto masivo. |
| **Duración e Indisponibilidad de Servicio Crítico** | DORA Art. 18(1)(b) / RTS Art. 2 | 🔴 DISPARADO | `2.50 horas (Servicio Crítico: True)` | >= 2.0 horas en función esencial | Servicio crítico en caída por 2.50 horas (Umbral: 2.0h). |
| **Impacto Económico Directo e Indirecto** | DORA Art. 18(1)(c) / RTS Art. 3 | 🔴 DISPARADO | `180,000.00 €` | >= 100,000.00 € | Pérdidas estimadas de 180,000.00 € superan el umbral cuantitativo. |
| **Extensión Geográfica transfronteriza** | DORA Art. 18(1)(d) / RTS Art. 4 | 🔴 DISPARADO | `2 Estados Miembros UE` | >= 2 países UE | Incidente con impacto transfronterizo en 2 países de la Unión Europea. |
| **Pérdida de Datos o Brecha de Confidencialidad** | DORA Art. 18(1)(e) / RTS Art. 5 | 🟢 NORMAL | `Integridad alterada: False, Brecha: False` | Cualquier alteración no autorizada de datos críticos o exfiltración | No se reportan alteraciones de datos ni exfiltración de confidencialidad. |


---

## 3. Acciones Recomendadas y Siguientes Pasos

1. 🚨 **Activar Gabinete de Crisis e Incidentes TIC.**
2. ⏱️ **Notificación Inicial de Alerta (Fase 1):** Preparar y enviar reporte inicial a la Autoridad Competente en un plazo máximo de **2 horas** (Art. 19.4).
3. 🔒 **Registrar en el Bitácora Inmutable:** Asegurar que los logs de detección y respuesta se encuentren firmados en almacén WORM.
4. 📄 **Preparar Informe Intermedio (Fase 2):** Reporte de progreso en **24 horas**.

---
*Evaluado por `dora_incident_classifier.py` el 2026-07-25T14:17:05.375029+00:00*
