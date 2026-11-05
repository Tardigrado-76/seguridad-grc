# POLÍTICA DE BASTIONADO DE SISTEMAS Y HARDENING PERIMETRAL
**Normativa:** IP & PE Kernel Hardening Standards (DISA STIG, CIS Benchmarks)  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

---

## 1. REQUISITOS DE HARDENING DE KERNEL Y PROCESOS

### 1.1 Bastionado de Servidores VPS / Linux
- Desactivación de autenticación SSH por contraseña y acceso root directo.
- Configuración de cortafuegos IPTables/NFTables restringido con políticas de denegación por defecto (Drop All Inbound).
- **Evidencia Técnica de Ejecución:** `harden_vps.sh`.

### 1.2 Bastionado de Windows / LSA Protection (RunAsPPL)
- Activación obligatoria de la protección de procesos LSA (RunAsPPL) para mitigar extracción de credenciales en memoria (lsass dump / Mimikatz).
- **Evidencia Técnica de Ejecución:** `bunker_init_alta.ps1`.

### 1.3 Auditoría de Seguridad del Kernel y Resiliencia Anti-DDoS
- Inspección de sysctl, ASLR, mmap_min_addr y mitigaciones Meltdown/Spectre.
- Simulación continua de estrés y ataques DDoS para validar el rendimiento y las reglas de filtrado perimetral.
- **Evidencia Técnica de Ejecución:** `ip_pe_kernel_hardening_auditor.py`, `ddos_simulator.py`.

---

## 2. MATRIZ DE REQUISITOS HARDENING Y EVIDENCIAS

| Requisito | Estándar | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Bastionado VPS Linux | CIS Benchmark / DISA STIG | **CUMPLE 100%** | `harden_vps.sh` |
| LSA RunAsPPL & Windows | DISA STIG Windows | **CUMPLE 100%** | `bunker_init_alta.ps1` |
| Auditoría Kernel Linux | Kernel Hardening Spec | **CUMPLE 100%** | `ip_pe_kernel_hardening_auditor.py` |
| Mitigación Anti-DDoS | Network Resiliency Spec | **CUMPLE 100%** | `ddos_simulator.py` |

---
*Alineación verificada y validada al 100% bajo estándares de Hardening Perimetral.*
