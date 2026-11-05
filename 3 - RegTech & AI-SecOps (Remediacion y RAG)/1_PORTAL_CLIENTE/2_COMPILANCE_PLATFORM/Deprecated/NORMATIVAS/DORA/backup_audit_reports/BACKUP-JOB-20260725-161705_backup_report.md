# Reporte de Copias de Seguridad Cifradas (ENS Alto / NIS2 / DORA)

**ID Operación:** `BACKUP-JOB-20260725-161705`  
**Tipo de Operación:** **BACKUP**  
**Fecha de Ejecución:** 2026-07-25T14:17:05.246644+00:00  
**Estado General:** ✅ COPÌAS DE SEGURIDAD CIFRADAS CON ÉXITO  
**Hash de Integridad:** `ea7e7ba5e2a3ecd8...`  

---

## 1. Resumen de Respaldos de Bases de Datos

- **Bases de Datos Procesadas:** 1
- **Copias Cifradas Exitosas:** 1
- **Bases de Datos con Error:** 0
- **Sanitización Temporal NIST 800-88:** ✅ APLICADA EN TODOS LOS EVENTOS

---

## 2. Detalle de Archivos Cifrados AES-256-GCM

| BD Origen | Archivo Cifrado Resultante | Tamaño | Checksum SHA-256 | Algoritmo |
|-----------|----------------------------|--------|------------------|-----------|
| `audit_events.db` | `audit_events_backup_20260725_161705.enc` | 8220 B | `2e9234f5f86fe7cd...` | AES-256-GCM |


---

## 3. Normativa de Resiliencia y Protección de Datos

> **NIS2 Art. 21 & ENS Alto Art. 22:** Exigen el cifrado fuerte e incondicional de todas las
> copias de seguridad de datos esenciales, asegurando la destrucción segura de residuos en memoria o disco (NIST SP 800-88).

---
*Generado por `bunker_secure_backup.py` el 2026-07-25T14:17:05.246644+00:00*
