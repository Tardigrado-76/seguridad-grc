# Auditoría Criptográfica TLS 1.3 / PQC Híbrida (ENS Alto / DORA Art. 9)

**ID Auditoría:** `TLS-AUDIT-20260725-161521`  
**Ubicación Certificados:** `E:\PROYECTOS IA\AUDITORIAS\DORA\certs\server.crt`  
**Fecha de Verificación:** 2026-07-25T14:15:22.713993+00:00  
**Estado Criptográfico:** ✅ CERTIFICADOS VALIDOS Y CIFRADO PQC ACTIVO  
**Hash de Integridad:** `73c7096ac5975855...`  

---

## 1. Parámetros del Certificado X509

| Parámetro | Valor Registrado |
|-----------|------------------|
| **Estado Certificado** | ✅ VÁLIDO |
| **Días hasta Expiración** | **198 días** |
| **Fecha de Caducidad** | `2027-02-09T14:15:22+00:00` |
| **Tamaño de Clave RSA** | 4096 bits |
| **Algoritmo de Firma** | `sha384` |
| **Rotación Requerida (<10 días)** | `NO` |

---

## 2. Configuración de Criptografía Post-Cuántica (PQC FIPS Standards)

- **Modo Híbrido TLS PQC:** **True**
- **Intercambio de Claves KEM:** `X25519_MLKEM768 (FIPS 203)`
- **Firma Digital de Handshake:** `ML-DSA-65 (FIPS 204)`
- **Firma Sin Estado (Larga Duración):** `SLH-DSA-SHA2-128F (FIPS 205)`

---

## 3. Normativa y Hardening Criptográfico

> **ENS Alto Art. 14 & DORA Art. 9:** Exigen el uso de algoritmos de cifrado robustos,
> la rotación obligatoria de certificados antes de su caducidad y la preparación ante la
> amenaza de ordenadores cuánticos mediante estándares PQC de NIST/FIPS (203/204/205).

---
*Generado por `tls_config.py` el 2026-07-25T14:15:22.713993+00:00*
