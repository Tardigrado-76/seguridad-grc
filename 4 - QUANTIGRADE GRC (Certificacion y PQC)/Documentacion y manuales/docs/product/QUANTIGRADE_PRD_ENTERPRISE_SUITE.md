# Documento de Requisitos de Producto (PRD): Quantigrade GCR Enterprise Suite v3.0 - v5.0

## 1. Resumen Ejecutivo
Quantigrade GCR es la plataforma soberana de Gestión de Gobierno, Riesgo y Cumplimiento (GRC) de siguiente generación. Diseñada desde cero con una arquitectura **Cero Docker**, **Cero Mocks** y **Criptografía Post-Cuántica (PQC NIST FIPS 204)**, transforma los procesos manuales y burocráticos de auditoría en una malla activa y continua de verificación y remediación.

---

## 2. Matriz de Priorización RICE

| Característica / Capacidad | Reach (Alcance) | Impact (Impacto) | Confidence (Confianza) | Effort (Esfuerzo) | RICE Score | Versión |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Inference Firewall & DLP Guard** | 100% Clientes IA | 3 (Masivo) | 90% | 1.5 | **180** | **v3.0 (Actual)** |
| **Legal & Financial Guard (Actuarial)** | 100% C-Level | 3 (Crítico) | 95% | 1.0 | **285** | **v3.0 (Actual)** |
| **Mapeo Normativo Cruzado (Mesh)** | 90% Empresas | 2.5 (Alto) | 90% | 1.0 | **202** | **v3.0 (Actual)** |
| **Despachador n8n Cero-Docker** | 80% Equipos SecOps | 2 (Alto) | 95% | 1.0 | **152** | **v3.0 (Actual)** |
| **Conectores SCIM & SSO SAML/OIDC** | 75% Enterprise | 2 (Medio) | 90% | 2.0 | **67** | **v3.5** |
| **Auditoría Forense eBPF en Linux** | 60% Cloud | 2.5 (Alto) | 80% | 3.0 | **40** | **v4.0** |
| **Consenso Distribuido P2P Entre Nodos** | 30% Consorcios | 1.5 (Nicho) | 70% | 4.0 | **8** | **v5.0** |

---

## 3. Especificación Funcional de Versiones

### Versión 3.0 (Hito Actual: Blindaje Core & Remediación Automática)
- **Motor Criptográfico Merkle Bunker:** Árboles Merkle con hash-chain SQLite WAL y Dilithium3 (NIST FIPS 204).
- **Sellado Temporal Cualificado eIDAS 2.0 (RFC 3161):** Evidencia admisible en juicio penal (Art. 31 bis CP).
- **Firewall de Inferencia & DLP:** Sanitización de PII y bloqueo de prompt injection bajo EU AI Act.
- **Calculadora de Responsabilidad Directiva y Contingencias:** Exposición de administradores bajo NIS2 Art. 20.
- **Despacho n8n y Malla Cruzada:** Reducción de fatiga de auditoría propagando un 150%+ de evidencias.

### Versión 3.5 (Enterprise Identity & Multi-Cloud Federation)
- Integración nativa con Azure Entra ID, Okta y PingFederate vía SAML 2.0 y OIDC sin dependencias de Docker.
- Aprovisionamiento automático de usuarios (SCIM 2.0) y RBAC federado por roles de auditoría.
- Conectores de lectura de solo lectura para auditoría continua de AWS CloudTrail, Azure Policy y Google Cloud Security Command Center.

### Versión 4.0 (Autonomous Healing & Kernel-Level Probes)
- **Sondas eBPF Nativas:** Verificación de inmutabilidad de sockets de red y llamadas al sistema en tiempo de ejecución sin agentes pesados.
- **Auto-Remediación con Rollback Criptográfico:** Playbooks que ejecutan el cambio y, si el test de integridad falla, revierten el estado del sistema inmediatamente (*fail-closed*).
- **Portal de Confianza Público Dinámico (Live Trust Center):** Página de estado de cumplimiento en tiempo real para clientes y auditores externos con verificación criptográfica instantánea.

### Versión 5.0 (Red Consorciada de Cumplimiento Soberano)
- Intercambio de pruebas de cumplimiento Zero-Knowledge (ZKP) entre entidades financieras y reguladores sin exponer datos de clientes.
- Pasaporte regulatorio digital paneuropeo emitido bajo marco EBSI (European Blockchain Services Infrastructure).

---

## 4. Requisitos No Funcionales (SLA & Compliance)
1. **Rendimiento:** Evaluación completa de la suite de 20 marcos en menos de 3 segundos sobre hardware estándar.
2. **Soberanía y Huella:** Cero contenedores Docker, cero telemetría externa hacia servidores fuera de la UE.
3. **Resiliencia:** Operación continua en modo *Air-Gapped* 100% desconectado de Internet.
