# INFORME CONSOLIDADO DE AUDITORÍA DEVSECOPS Y RGPD (PROD)
- **Organización / Perfil:** Perfil 1 - Empresa Privada / Pyme IT
- **Modo de Auditoría:** PRODUCCIÓN REAL
- **Fecha de Ejecución:** 2026-07-28T16:30:33.178768+00:00
- **Auditor Responsable:** Tardigrado
- **Sistema Host:** N16 (Windows)

## MAPEO CRUZADO DE CONTROLES (CROSS-CONTROL MAPPING)
| Fase | Módulo Técnico | Estado | Mapeo Cruzado (RGPD / OWASP / CRA) |
| :---: | :--- | :---: | :--- |
| 01 | Inventario de dependencias (SBOM) | **SKIPPED** | RGPD Art. 32 (Seguridad del Tratamiento) | CRA (Cadena de Suministro) |
| 02 | Análisis Estático SAST (AST Scan) | **SKIPPED** | CRA (Seguridad del Código Fuente) | OWASP Top 10 A06 | RGPD Art. 32 |
| 03 | Control de Acceso (BOLA/IDOR) | **COMPLETED** | OWASP Top 10 A01 (BOLA/IDOR) | CRA (Control de Acceso API) | RGPD Art. 32 |
| 04 | Extractor DSAR (RGPD Art. 15) | **COMPLETED** | RGPD Art. 15 (Derecho de Acceso del Interesado / DSAR) |
| 05 | Verificación Notificación Brechas | **SKIPPED** | RGPD Art. 33/34 (Notificación de Brechas AEPD / Afectados) |
| 06 | Purga y Minimización de Datos | **SKIPPED** | RGPD Art. 5.1.e (Conservación) | RGPD Art. 17 (Supresión / Olvido) |
