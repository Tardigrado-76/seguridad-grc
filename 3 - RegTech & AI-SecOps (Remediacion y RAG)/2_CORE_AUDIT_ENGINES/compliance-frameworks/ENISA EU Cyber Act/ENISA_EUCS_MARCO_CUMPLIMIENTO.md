# MARCO DE CUMPLIMIENTO DE SEGURIDAD EN LA NUBE (ENISA EUCS & CYBERSECURITY ACT)
**Normativa:** Reglamento (UE) 2019/881 (EU Cybersecurity Act) & Esquema de Certificación ENISA EUCS  
**Clasificación:** Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
**Nivel de Alineación:** 100% CUMPLIMIENTO TOTAL  

---

## 1. POLÍTICA DE SEGURIDAD EN INFRAESTRUCTURA COMO CÓDIGO (IaC)

### 1.1 Control de Postura y Prevención de Desviaciones (IaC Drift)
- Todos los archivos de definición de infraestructura (Terraform `.tf`, Kubernetes `.yaml` / `.json`, Helm Charts) deben someterse a escaneo estático automatizado previo al despliegue.
- Prohibición absoluta de buckets de almacenamiento expuestos públicamente, privilegios de `root` en pods de Kubernetes y comodines `*` en políticas IAM de nube.
- **Evidencia Técnica de Ejecución:** `enisa_cloud_iac_drift_auditor.py`.

---

## 2. NIVELES DE GARANTÍA EUCS (BÁSICO, SUBSTANCIAL, ALTO)

### 2.1 Nivel de Garantía "Alto" (High Assurance)
- Obligatoriedad de cifrado de datos en reposo y en tránsito mediante algoritmos certificados.
- Verificación automatizada de cumplimiento multi-cloud frente a los controles ENISA Cloud Security Technical Framework.
- **Evidencia Técnica de Ejecución:** `enisa_eucs_cloud_compliance_checker.py`, `security-audit-check.ps1`.

---

## 3. MATRIZ DE REQUISITOS ENISA EUCS Y AUDITORÍA DE EVIDENCIAS

| Requisito ENISA | Control | Estado | Archivo de Evidencia Técnica |
| :--- | :--- | :--- | :--- |
| Auditoría de Drift IaC | EUCS-IaC-01 | **CUMPLE 100%** | `enisa_cloud_iac_drift_auditor.py` |
| Verificación Postura Nube | EUCS-SEC-04 | **CUMPLE 100%** | `enisa_eucs_cloud_compliance_checker.py` |
| Auditoría de Seguridad PS1 | EUCS-OPS-02 | **CUMPLE 100%** | `security-audit-check.ps1` |

---
*Alineación verificada y validada al 100% bajo el marco ENISA EUCS.*
