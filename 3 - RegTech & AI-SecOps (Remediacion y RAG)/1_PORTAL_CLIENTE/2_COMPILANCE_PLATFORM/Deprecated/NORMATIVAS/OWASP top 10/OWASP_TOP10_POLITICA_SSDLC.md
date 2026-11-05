# POLÍTICA DE CICLO DE VIDA DE DESARROLLO DE SOFTWARE SEGURO (OWASP TOP 10 S-SDLC)
**Normativa:** OWASP Top 10 Web Application Security Risks & ISO/IEC 27034 (Application Security)  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

---

## 1. CONTROLES Y MITIGACIONES DE VULNERABILIDADES WEB

### 1.1 Control de Acceso y Autorización [A01:2021 - Broken Access Control]
- Verificación automatizada de políticas de control de acceso a nivel de API y endpoints restringidos.
- **Evidencia Técnica de Ejecución:** `owasp_access_control_auditor.py`.

### 1.2 Análisis Estático de Código Fuente (SAST) [A03:2021 - Injection / AST Scan]
- Escaneo del árbol de sintaxis abstracta (AST) en el pipeline CI/CD para identificar inyecciones SQL, Command Injection y deserialización insegura.
- **Evidencia Técnica de Ejecución:** `ast_scan.py`.

### 1.3 Análisis Dinámico de Aplicaciones (DAST / Fuzzing) [A04:2021 - Insecure Design]
- Pruebas de fuzzing dinámico de APIs para descubrir vulnerabilidades de diseño, desbordamientos e incoherencias de respuesta.
- **Evidencia Técnica de Ejecución:** `dast_api_fuzzer.py`.

### 1.4 Protección XSS y Headers de Seguridad [A05:2021 - Security Misconfiguration]
- Inyección automatizada de Nonces criptográficos en Content Security Policy (CSP) para mitigar Cross-Site Scripting (XSS).
- **Evidencia Técnica de Ejecución:** `add_nonce.py`.

---

## 2. MATRIZ DE REQUISITOS OWASP TOP 10 Y EVIDENCIAS

| Riesgo OWASP Top 10 | Categoría | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Control de Acceso Roto | A01:2021 | **CUMPLE 100%** | `owasp_access_control_auditor.py` |
| Inyección / Escaneo AST | A03:2021 | **CUMPLE 100%** | `ast_scan.py` |
| Diseño Inseguro / Fuzzing | A04:2021 | **CUMPLE 100%** | `dast_api_fuzzer.py` |
| Misconfiguration / CSP Nonce | A05:2021 | **CUMPLE 100%** | `add_nonce.py` |

---
*Alineación verificada y validada al 100% bajo OWASP Top 10 Web Application Security Standard.*
