# Memoria Técnica de Homologación CPSTIC: Quantigrade GCR

## 1. Identificación del Producto y Fabricante
- **Nombre Comercial del Producto:** Quantigrade GCR Master Suite
- **Versión Evaluada:** 3.0.0 Enterprise Soberana
- **Familia CPSTIC Solicitada:** *Herramientas de Auditoría, Monitorización y Cumplimiento del ENS*
- **Nivel de Cualificación Solicitado:** **ENS Categoría ALTA** (RD 311/2022)
- **Guías CCN-STIC de Referencia:** CCN-STIC 105 (Catálogo CPSTIC), CCN-STIC 140 (Guía de Evaluación), CCN-STIC 808 (Verificación del ENS), CCN-STIC 817 (Gestión de Ciberincidentes) y CCN-STIC 893 (Criptografía Post-Cuántica).

---

## 2. Declaración de Cumplimiento de Criterios Fundamentales

### 2.1 Cero Dependencias de Contenedores Externos (Zero-Docker Mandate)
Quantigrade GCR está diseñado desde el código fuente para ejecutarse íntegramente en Python nativo sobre sistemas operativos corporativos certificados (Windows Server / RHEL / Ubuntu LTS).
- **Justificación de Seguridad:** Elimina por completo las vulnerabilidades inherentes a la cadena de suministro de imágenes de contenedores, fugas de socket (`docker.sock`) y elevación de privilegios en el kernel del host, haciéndolo apto para redes clasificadas y entornos **Air-Gapped (SARA / TESTA)**.

### 2.2 Integridad Probatoria Inmutable (Merkle Bunker & PQC NIST FIPS 204)
Todas las trazas de auditoría, evidencias técnicas y deliberaciones agénticas se encadenan mediante árboles Merkle respaldados en SQLite con modo WAL (`journal_mode=WAL`) y firmas post-cuánticas ML-DSA-87 (Dilithium3).
- **Conformidad CCN-STIC 893:** Protección frente al Teorema de Mosca y ataques *Harvest Now, Decrypt Later*.

### 2.3 Ausencia de Mocks y Telemetría Oculta
La plataforma rechaza de forma determinista la simulación estática (*zero mocks*). Toda métrica de cumplimiento se basa en la extracción de evidencia verificable sobre el sistema objetivo. Cero telemetría hacia servidores fuera de la Unión Europea.

---

## 3. Matriz de Cumplimiento del Esquema Nacional de Seguridad (ENS Nivel ALTO)

| Código ENS | Medida de Seguridad | Implementación Técnica en Quantigrade GCR | Estado de Conformidad |
| :--- | :--- | :--- | :---: |
| **org.1** | Política de Seguridad | Verificación automatizada de existencia, vigencia y aprobación por el Consejo/Comité. | **CONFORME** |
| **org.2** | Roles y Responsabilidades | Segregación estricta de mandatos con `RegulatoryRoleRegistry` (CISO, DPO, Auditor, Red Team). | **CONFORME** |
| **op.pl.1** | Planificación y Continuidad | Verificación de RPO/RTO y pruebas periódicas de contingencia TIC. | **CONFORME** |
| **op.acc.1** | Control de Acceso y MFA | Validación de MFA reforzado (FIDO2 / PIV) y revocación inmediata de cuentas inactivas. | **CONFORME** |
| **op.exp.8** | Notificación de Incidentes | Pasarela nativa `LuciaCsirtGateway` (STIX 2.1 / CCN-STIC 817) para notificación en 24h/72h al CCN-CERT. | **CONFORME** |
| **mp.info.3** | Copias de Seguridad | Comprobación de inmutabilidad WORM y aislamiento lógico de copias de seguridad. | **CONFORME** |
| **mp.com.1** | Cifrado de Comunicaciones | Auditoría continua de TLS 1.3 y compatibilidad post-cuántica bajo Guía CCN-STIC 893. | **CONFORME** |
| **mp.si.1** | Protección frente a Malware | Verificación de inventario SBOM (CRA Art. 10) y correlación con vulnerabilidades conocidas (CISA KEV). | **CONFORME** |

---

## 4. Capacidades Específicas para la Administración Pública Española

### 4.1 Exportación Directa al Sistema INES (Informe Nacional del Estado de Seguridad)
Quantigrade GCR incorpora el módulo `InesCcnExporter`, que compila las evidencias operativas en el formato de importación oficial del CCN-CERT, reduciendo a cero el tiempo de preparación del informe anual obligatorio para organismos públicos.

### 4.2 Notificación Automatizada a LUCIA (CCN-CERT)
La pasarela `LuciaCsirtGateway` automatiza la remisión de incidentes en los plazos legales de la Directiva NIS2 (RD-ley 12/2018 y transposición NIS2): alerta temprana en 24h, notificación intermedia en 72h e informe final al mes.

### 4.3 Firma Electrónica Cualificada de Empleado Público
Mediante `FnmtQualifiedSigner`, los expedientes de auditoría son firmados electrónicamente mediante certificados de empleado público (FNMT-RCM / DNIe) e incorporan sellos de tiempo cualificados RFC 3161 (eIDAS 2.0 Art. 41), dotándolos de valor probatorio pleno ante cualquier tribunal o auditoría del Tribunal de Cuentas.
