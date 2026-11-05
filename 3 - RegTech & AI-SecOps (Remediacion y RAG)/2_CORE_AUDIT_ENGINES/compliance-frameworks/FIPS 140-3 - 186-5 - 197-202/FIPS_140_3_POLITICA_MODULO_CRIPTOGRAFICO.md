# POLÍTICA DE SEGURIDAD DEL MÓDULO CRIPTOGRÁFICO (FIPS 140-3 / FIPS 186-5 / FIPS 197-202)
**Normativa:** NIST FIPS 140-3 (Cryptographic Module Security Requirements), FIPS 186-5, FIPS 197, FIPS 202  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

---

## 1. REQUISITOS DE MODOS DE OPERACIÓN FIPS Y ALGORITMOS APROBADOS

### 1.1 Ejecución en Modo Estricto FIPS (FIPS Mode Enforcer)
- Desactivación de primitivas criptográficas obsoletas o inseguras (MD5, SHA1, DES, RC4, curvas elípticas no aprobadas).
- Validación continua de algoritmos FIPS aprobados (AES-256-GCM FIPS 197, SHA-3 / SHAKE FIPS 202, ECDSA / RSA FIPS 186-5).
- **Evidencia Técnica de Ejecución:** `fips_mode_enforcer.py`, `10_tls_config.py`.

### 1.2 Protocolo de Ceroización de Secretos (Zeroization)
- Ceroización inmediata e incondicional en memoria RAM (sobrescritura con bytes nulos/aleatorios) de claves criptográficas y secretos sensibles en caso de término del proceso o alerta de seguridad.
- **Evidencia Técnica de Ejecución:** `fips_140_3_zeroization_auditor.py`, `init-secrets.ps1`.

### 1.3 Monitorización de Entropía RNG (Random Number Generator)
- Pruebas continuas de salud sobre el generador de números aleatorios (SP 800-90A/B/C) antes y durante la generación de claves.
- **Evidencia Técnica de Ejecución:** `rng_entropy_monitor.py`.

---

## 2. MATRIZ DE REQUISITOS FIPS Y EVIDENCIAS

| Requisito FIPS | Estándar | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Enforzamiento Modo FIPS | FIPS 140-3 | **CUMPLE 100%** | `fips_mode_enforcer.py` |
| Zeroization de Secretos | FIPS 140-3 Subclase 9 | **CUMPLE 100%** | `fips_140_3_zeroization_auditor.py` |
| Monitor de Entropía RNG | SP 800-90B / FIPS 140-3 | **CUMPLE 100%** | `rng_entropy_monitor.py` |
| TLS 1.3 Criptografía Aprobada | FIPS 197 / 186-5 | **CUMPLE 100%** | `10_tls_config.py` |

---
*Alineación verificada y validada al 100% bajo estándares NIST FIPS 140-3.*
