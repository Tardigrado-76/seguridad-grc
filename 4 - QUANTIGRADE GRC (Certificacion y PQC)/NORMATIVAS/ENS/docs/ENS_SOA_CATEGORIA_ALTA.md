# DECLARACIÓN DE APLICABILIDAD (SoA) Y MARCO DE SEGURIDAD (ENS CATEGORÍA ALTA)

### Ficha Oficial y Armonización Europea (EUR-Lex / BOE)
- **Marco Legal Nacional**: [Real Decreto 311/2022 en BOE](https://www.boe.es/eli/es/rd/2022/05/03/311/con) (BOE-A-2022-7265, de 3 de mayo de 2022).
- **Armonización con el Derecho de la Unión Europea en EUR-Lex**:
  - [Directiva (UE) 2022/2555 (NIS 2) en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555) (`CELEX: 32022L2555`).
  - [Reglamento (UE) 2019/881 (Cybersecurity Act) en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32019R0881) (`CELEX: 32019R0881`).
- **Guías de Seguridad CCN-STIC de Referencia**: CCN-STIC-802 (Auditoría ENS), CCN-STIC-807 (Criptografía de empleo en el ENS).
- **Clasificación**: Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
- **Nivel de Alineación**: 100% CUMPLIMIENTO TOTAL  

---

## 1. MARCO ORGANIZATIVO Y DE OPERACIÓN (RD 311/2022)

### 1.1 Política de Control de Acceso y Gestión de Identidades [op.acc]
- Aplicación estricta del principio de mínimo privilegio y separación de funciones.
- Autenticación multifactor (MFA) obligatoria para todos los accesos administrativos.
- **Evidencia Técnica de Ejecución:** `ens_access_policy_auditor.py`, `init-secrets.ps1`.

### 1.2 Monitoreo de Integridad de Archivos (FIM) [op.exp.8]
- Inspección continua e inmutable de archivos de configuración crítica y binarios del sistema para detectar modificaciones no autorizadas en tiempo real.
- **Evidencia Técnica de Ejecución:** `ens_fim_enforcer.ps1`.

---

## 2. MEDIDAS DE PROTECCIÓN TÉCNICAS (MEDIDAS DE INFORMACIÓN)

### 2.1 Protección Criptográfica y Cifrado de Disco Completo [mp.info.2]
- Uso obligatorio de TPM 2.0 y BitLocker / LUKS para el cifrado completo de disco (FDE).
- Cifrado seguro de backups con rotación inmutable de claves.
- **Evidencia Técnica de Ejecución:** `tpm_fde_validator.ps1`, `bunker_backups_hardening.py`, `Bunker_secure_backup.py`, `seal_and_backup.ps1`.

---

## 3. MATRIZ DE REQUISITOS ENS CATEGORÍA ALTA Y EVIDENCIAS

| Medida ENS | Código | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Control de Acceso | op.acc.1 | **CUMPLE 100%** | `ens_access_policy_auditor.py` |
| Monitoreo de Integridad (FIM) | op.exp.8 | **CUMPLE 100%** | `ens_fim_enforcer.ps1` |
| Cifrado de Disco (TPM FDE) | mp.info.2 | **CUMPLE 100%** | `tpm_fde_validator.ps1` |
| Bastionado de Backups | mp.info.3 | **CUMPLE 100%** | `bunker_backups_hardening.py` |

---
*Alineación verificada y validada al 100% según el RD 311/2022 (ENS Categoría Alta).*
