# Marco de Cumplimiento eIDAS 2.0 (Reglamento UE 2024/1183)
## Cartera Europea de Identidad Digital (EUDI Wallet) y Servicios de Confianza Cualificados

### 1. Ficha Oficial EUR-Lex
- **Enlace Oficial EUR-Lex**: [Regulation (EU) 2024/1183 en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1183)
- **Número CELEX**: `32024R1183`
- **Título Oficial**: *Reglamento (UE) 2024/1183 del Parlamento Europeo y del Consejo, de 11 de abril de 2024, por el que se modifica el Reglamento (UE) n.° 910/2014 en lo que respecta al establecimiento del Marco Europeo de Identidad Digital.*
- **Publicación Oficial**: Diario Oficial de la Unión Europea (DO L, 2024/1183, 30.4.2024).
- **Entrada en Vigor**: 20 de mayo de 2024.
- **Plazos de Obligación (EUDI Wallet)**: Estados miembros obligados a proporcionar carteras de identidad digital a los ciudadanos a más tardar 24 meses tras la adopción de los actos de ejecución (2026).

---

### 2. Módulos y Arquitectura Técnica Alineada con EUR-Lex

| Componente Técnico | Archivo Fuente | Artículos EUR-Lex Cumplidos | Especificación Técnica Armonizada |
| :--- | :--- | :--- | :--- |
| **EUDI Wallet Manager** | `engines/eidas2_eudi_wallet_manager.py` | **Art. 6a**, **Art. 6b**, **Art. 6c** | ETSI TS 119 461 / Architecture and Reference Framework (ARF v1.4). Gestión de enclave criptográfico seguro (eSE/SIM), par de claves bajo control exclusivo del usuario, divulgación selectiva (*Selective Disclosure* / SD-JWT) y no trazabilidad (*Zero-Knowledge*). |
| **QES Signature Engine** | `engines/eidas2_qes_signature_engine.py` | **Arts. 25, 26, 28, 32** | ETSI EN 319 142 (PAdES-B-LTA), ETSI EN 319 132 (XAdES). Creación de Firmas Electrónicas Cualificadas (QES) con plena equivalencia jurídica a la firma manuscrita en toda la Unión. |
| **EAA Attribute Attestator** | `engines/eidas2_eaa_attribute_attestator.py` | **Arts. 45a - 45f** | W3C Verifiable Credentials Data Model v2.0 / OpenID for Verifiable Credential Issuance (OID4VCI). Emisión y verificación de Atestaciones Electrónicas de Atributos cualificadas (QEAA) emitidas por autoridades públicas o QTSP. |
| **Evaluador Central GCR** | `evaluators/eidas2.py` | Todos los Capítulos eIDAS 2.0 | Motor de auditoría automatizada conforme a `BaseEvaluator` para scoring continuo y reporte ejecutivo. |
| **Dashboard / Consola** | `dashboards_apps/eidas2_wallet_portal.py` | **Art. 6a(4)** | Interfaz Streamlit y CLI para monitorización de estados criptográficos, credenciales y firmas cualificadas. |

---

### 3. Controles Auditados y Evidencias Conforme a EUR-Lex

1. **Art. 6a - Requisitos de la Cartera Europea de Identidad Digital (EUDI Wallet):**
   - Nivel de Seguridad Alto (*Level of Assurance High - LoA High* conforme al Reglamento de Ejecución (UE) 2015/1502).
   - Generación de claves criptográficas y almacenamiento en enclave de hardware seguro (eSE / TPM 2.0 / SIM).
   - Mecanismo de divulgación selectiva: el emisor no puede rastrear los usos de la cartera y la parte usuaria solo recibe los atributos estrictamente consentidos.
2. **Arts. 25 & 26 - Efectos Jurídicos de las Firmas y Sellos Cualificados:**
   - La firma electrónica cualificada tiene un efecto jurídico equivalente al de una firma manuscrita en los 27 Estados Miembros de la UE (Art. 25.2).
   - Verificación de la inclusión del prestador en la Lista de Confianza Europea (*EU Trusted List* - QTSP).
3. **Art. 45a - Atestación Electrónica de Atributos Cualificada (QEAA):**
   - Garantía de autenticidad e integridad mediante firma/sello electrónico cualificado del emisor.
   - Prevención de correlación de identificadores de usuario entre distintos prestadores de servicios.

---

### 4. Mapeo Transversal con Normativas GCR
- **ISO/IEC 27001:2022**: A.5.15 (Control de accesos), A.8.24 (Uso de criptografía).
- **SOC 2 Type II**: CC6.1 (Controles lógicos de acceso), CC6.3 (Gestión de identidades).
- **ENS Categoría Alta**: [op.acc.1] Identificación y autenticación, [mp.cr.1] Criptografía.
