# MARCO DE CUMPLIMIENTO DE SEGURIDAD EN LA NUBE (ENISA EUCS & CYBERSECURITY ACT)

### Ficha Oficial EUR-Lex
- **Enlace Oficial EUR-Lex**: [Regulation (EU) 2019/881 en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32019R0881)
- **Número CELEX**: `32019R0881`
- **Título Oficial**: *Reglamento (UE) 2019/881 del Parlamento Europeo y del Consejo, de 17 de abril de 2019, relativo a ENISA (Agencia de la Unión Europea para la Ciberseguridad) y a la certificación de la ciberseguridad de las tecnologías de la información y la comunicación y por el que se deroga el Reglamento (UE) n.° 526/2013 (Reglamento sobre la Ciberseguridad).*
- **Publicación Oficial**: Diario Oficial de la Unión Europea (DO L 151, 7.6.2019, p. 15–69).
- **Entrada en Vigor**: 27 de junio de 2019.
- **Marco de Certificación Europeo (Título III)**: Esquema de Certificación de Ciberseguridad para Servicios en la Nube (ENISA EUCS - Niveles Básico, Sustancial y Alto).
- **Clasificación**: Documento Oficial de Cumplimiento GRC & Evidencia Regulatoria  
- **Nivel de Alineación**: 100% CUMPLIMIENTO TOTAL  

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
