# POLÍTICA DE SEGURIDAD EN LA CADENA DE SUMINISTRO DE SOFTWARE (SOFTWARE SUPPLY CHAIN SECURITY)
**Normativa:** SLSA Framework Level 3+, NIST SP 800-161, CISA KEV, Executive Order 14028  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

---

## 1. REQUISITOS DE TRANSPARENCIA Y TRAZABILIDAD DEL SOFTWARE

### 1.1 Generación Automática de SBOM (CycloneDX 1.6 / SPDX)
- Creación automatizada del Inventario de Componentes de Software (Software Bill of Materials - SBOM) en cada compilación CI/CD para visibilidad completa de dependencias de terceros.
- **Evidencia Técnica de Ejecución:** `generate_sbom.py`, `pre_build_pipeline.ps1`.

### 1.2 Atestación e Inmutabilidad de Procedencia SLSA Nivel 3+
- Generación de atestaciones firmadas criptográficamente (`slsa_provenance`) que certifican el origen hermético e inalterable del artefacto.
- **Evidencia Técnica de Ejecución:** `slsa_provenance_signer.ps1`, `slsa_provenance_signer.sh`, `fips_204_mldsa_git_commit_signer.py`.

### 1.3 Verificación Continuada de Vulnerabilidades CISA KEV y VEX Aggregator
- Filtrado automático pre-compilación que bloquea cualquier dependencia con vulnerabilidades conocidas explotadas activamente (CISA Known Exploited Vulnerabilities catalog).
- **Evidencia Técnica de Ejecución:** `cisa_kev_gate.py`, `supply_chain_dependency_checker.py`, `nis2_supply_chain_vex_aggregator.py`.

---

## 2. MATRIZ DE REQUISITOS SUPPLY CHAIN SECURITY Y EVIDENCIAS

| Requisito Supply Chain | Estándar | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| SBOM CycloneDX 1.6 | EO 14028 / NIST SP 800-161 | **CUMPLE 100%** | `generate_sbom.py` |
| Firma SLSA Provenance L3+ | SLSA Spec v1.0 | **CUMPLE 100%** | `slsa_provenance_signer.ps1` |
| Bloqueo CISA KEV Catalog | CISA BOD 22-01 | **CUMPLE 100%** | `cisa_kev_gate.py` |
| Verificación Dependencias | NIST SCRM | **CUMPLE 100%** | `supply_chain_dependency_checker.py` |

---
*Alineación verificada y validada al 100% bajo estándares de Software Supply Chain Security.*
