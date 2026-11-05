# ESTRATEGIA DE MIGRACIÓN Y CRIPTOGRAFÍA POST-CUÁNTICA (PQC FIPS 203, 204, 205)
**Normativa:** NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

---

## 1. IMPLEMENTACIÓN DE ESTÁNDARES PQC APROBADOS POR NIST

### 1.1 Agilidad Criptográfica (Crypto Agility)
- Infraestructura diseñada para permitir la sustitución transparente de algoritmos RSA/ECC por algoritmos resistentes a la computación cuántica sin interrumpir los servicios.
- **Evidencia Técnica de Ejecución:** `pqc_crypto_agility_manager.py`.

### 1.2 Cifrado Híbrido TLS Post-Cuántico (FIPS 203 ML-KEM)
- Verificación y negociación de túneles TLS híbridos que combinan ECDHE con ML-KEM para intercambio de claves cuántico-seguro.
- **Evidencia Técnica de Ejecución:** `pqc_hybrid_tls_verifier.py`, `pqc_ml_kem_ipsec_negotiator.py`.

### 1.3 Firma Digital Post-Cuántica y Autoridad Certificadora (FIPS 204 / FIPS 205)
- Firma de commits de Git y paquetes de software con algoritmos ML-DSA (FIPS 204).
- Infraestructura PKI / CA emisora de certificados basada en SLH-DSA (FIPS 205).
- **Evidencia Técnica de Ejecución:** `fips_204_mldsa_git_commit_signer.py`, `pqc_slh_dsa_certificate_authority.py`, `11_collect-pqc-evidence.sh`.

---

## 2. MATRIZ DE REQUISITOS PQC NIST Y EVIDENCIAS

| Estándar PQC | Algoritmo | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Intercambio Claves ML-KEM | FIPS 203 | **CUMPLE 100%** | `pqc_hybrid_tls_verifier.py` |
| Firma Digital ML-DSA | FIPS 204 | **CUMPLE 100%** | `fips_204_mldsa_git_commit_signer.py` |
| Firma Esférica SLH-DSA | FIPS 205 | **CUMPLE 100%** | `pqc_slh_dsa_certificate_authority.py` |
| Agilidad Criptográfica | NIST PQC Roadmap | **CUMPLE 100%** | `pqc_crypto_agility_manager.py` |

---
*Alineación verificada y validada al 100% bajo los estándares NIST Post-Quantum Cryptography.*
