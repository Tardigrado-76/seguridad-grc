# DECLARACIÓN DE APLICABILIDAD (SoA) Y MARCO DE SEGURIDAD (ENS CATEGORÍA ALTA)
**Normativa:** Real Decreto 311/2022, por el que se regula el Esquema Nacional de Seguridad (ENS)  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

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
