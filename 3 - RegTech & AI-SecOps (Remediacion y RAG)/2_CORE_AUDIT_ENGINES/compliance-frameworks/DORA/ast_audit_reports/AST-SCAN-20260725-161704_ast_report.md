# Informe de Auditoría AST de Dependencias (ENS Alto / NIS2 / DORA)

**ID Escaneo:** `AST-SCAN-20260725-161704`  
**Ruta Escaneada:** `E:\PROYECTOS IA\AUDITORIAS\DORA`  
**Fecha de Análisis:** 2026-07-25T14:17:05.103119+00:00  
**Estado Compliance:** ✅ CADENA DE SUMINISTRO ALINEADA  
**Hash de Integridad:** `71e92f1eda28df21...`  

---

## 1. Resumen de Análisis Sintáctico AST

- **Archivos `.py` Analizados:** 16
- **Total Dependencias Detectadas:** 3
- **Dependencias Instaladas y Verificadas:** 3
- **Dependencias Faltantes / No Instaladas:** 0 ⚠️
- **Errores de Lectura/Sintaxis:** 0

---

## 2. Dependencias No Instaladas (Riesgo en Cadena de Suministro)

✅ **Todas las dependencias de terceros importadas en el código están instaladas en el entorno.**


---

## 3. Dependencias Instaladas Verificadas

| Módulo Importado | Paquete PyPI | Ocurrencias en Código |
|------------------|--------------|-----------------------|
| `cryptography` | `cryptography` | 3 archivos |
| `fastapi` | `fastapi` | 1 archivos |
| `pydantic` | `pydantic` | 1 archivos |


---

## 4. Marco Normativo Aplicable

> **ENS (Nivel Alto) Art. 12 & NIS2 Art. 21(2)(d):** Exigen la identificación completa del software
> de terceros en producción, la comprobación de integridad y el control de dependencias para evitar
> ataques a la cadena de suministro (*Supply Chain Attacks*).

---
*Generado por `ast_scan.py` el 2026-07-25T14:17:05.103119+00:00*
