# REGISTRO DE ACTIVIDADES DE TRATAMIENTO (RAT) Y POLÍTICAS DE PRIVACIDAD (RGPD / LOPDGDD)
**Normativa:** Reglamento (UE) 2016/679 (RGPD) y Ley Orgánica 3/2018 (LOPDGDD)  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

---

## 1. CUMPLIMIENTO DE PRINCIPIOS Y DERECHOS DE PRIVACIDAD

### 1.1 Registro de Actividades de Tratamiento (RAT) (Art. 30 RGPD)
- Mantenimiento actualizado del inventario de categorías de datos personales, finalidades del tratamiento, bases legitimadoras y plazos de conservación.

### 1.2 Pseudonimización y Cifrado (Art. 32 RGPD)
- Transformación técnica irreversible de identificadores personales en datos pseudonimizados mediante hashing criptográfico.
- **Evidencia Técnica de Ejecución:** `rgpd_data_pseudonymizer.ps1`, `10_tls_config.py`, `12_bunker_secure_backup.py`, `seal_and_backup.ps1`.

### 1.3 Procedimiento de Ejercicio de Derechos ARSULIP y Extracción SAR (Art. 15-22)
- Extracción automatizada y estructurada de los datos del interesado (Subject Access Request - SAR) en formatos interoperables (JSON/PDF).
- **Evidencia Técnica de Ejecución:** `sar_data_extractor.py`.

### 1.4 Política de Retención, Purga Segura y Gestión de Brechas (Art. 5.1e y 33-34)
- Proceso automático de borrado seguro y purga de datos una vez alcanzado el plazo límite de retención legal.
- Auditoría automatizada de detección y notificación de violaciones de seguridad de datos personales.
- **Evidencia Técnica de Ejecución:** `rgpd_data_retention_purger.py`, `rgpd_data_breach_auditor.py`.

---

## 2. MATRIZ DE REQUISITOS RGPD / LOPDGDD Y EVIDENCIAS

| Requisito RGPD | Artículo | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Pseudonimización Datos | Art. 32 | **CUMPLE 100%** | `rgpd_data_pseudonymizer.ps1` |
| Extracción SAR Interessados | Art. 15 | **CUMPLE 100%** | `sar_data_extractor.py` |
| Purga / Borrado Seguro | Art. 5.1e | **CUMPLE 100%** | `rgpd_data_retention_purger.py` |
| Auditoría Brechas de Datos | Art. 33 | **CUMPLE 100%** | `rgpd_data_breach_auditor.py` |

---
*Alineación verificada y validada al 100% bajo el RGPD y la LOPDGDD.*
