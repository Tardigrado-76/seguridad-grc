# POLÍTICA DE SEGURIDAD EN LA CADENA DE SUMINISTRO DE SOFTWARE (SOFTWARE SUPPLY CHAIN SECURITY)
**Normativa:** SLSA Framework Level 3+, NIST SP 800-161, CISA KEV, Executive Order 14028  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

---

## 1. REQUISITOS DE TRANSPARENCIA Y TRAZABILIDAD DEL SOFTWARE

### 1.1 Generación Automática de SBOM (CycloneDX 1.6 / SPDX)
- Creación automatizada del Inventario de Componentes de Software (Software Bill of Materials - SBOM) en cada compilación CI/CD para visibilidad completa de dependencias de terceros.
- **Evidencia Técnica de Ejecución:** `core_mesh/operational/supply_chain_auditor.py`.

### 1.2 Atestación e Inmutabilidad de Procedencia SLSA Nivel 3+
- Generación de atestaciones firmadas criptográficamente (`slsa_provenance`) que certifican el origen hermético e inalterable del artefacto con digests duales SHA-256 y SHA-512.
- **Evidencia Técnica de Ejecución:** `core_mesh/operational/slsa_provenance_engine.py`, `core_mesh/operational/slsa_provenance_signer.ps1`, `core_mesh/operational/slsa_provenance_signer.sh`.

### 1.3 Verificación Continuada de Vulnerabilidades CISA KEV y VEX Aggregator
- Filtrado automático pre-compilación que bloquea cualquier dependencia con vulnerabilidades conocidas explotadas activamente (CISA Known Exploited Vulnerabilities catalog).
- **Evidencia Técnica de Ejecución:** `core_mesh/operational/supply_chain_auditor.py`.

---

## 2. MATRIZ DE REQUISITOS SUPPLY CHAIN SECURITY Y EVIDENCIAS

| Requisito Supply Chain | Estándar | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| SBOM CycloneDX / SPDX | EO 14028 / NIST SP 800-161 | **CUMPLE 100%** | `core_mesh/operational/supply_chain_auditor.py` |
| Firma SLSA Provenance L3+ | SLSA Spec v1.0 | **CUMPLE 100%** | `core_mesh/operational/slsa_provenance_engine.py` |
| Bloqueo CISA KEV & VEX | CISA BOD 22-01 / NIS2 | **CUMPLE 100%** | `core_mesh/operational/supply_chain_auditor.py` |
| Verificación Dependencias AST | NIST SCRM / CRA Art. 10 | **CUMPLE 100%** | `core_mesh/operational/ast_scanner.py` |

---
*Alineación verificada y validada al 100% bajo estándares de Software Supply Chain Security en QUANTIGRADE GCR.*

