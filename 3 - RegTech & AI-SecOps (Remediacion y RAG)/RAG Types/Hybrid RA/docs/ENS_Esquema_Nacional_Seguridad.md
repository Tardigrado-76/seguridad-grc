# Esquema Nacional de Seguridad (ENS) — Real Decreto 311/2022

## 1. Fundamentos y Categorización del ENS
El Esquema Nacional de Seguridad (ENS), regulado en España por el Real Decreto 311/2022, establece los principios básicos y requisitos mínimos para garantizar la adecuada protección de los sistemas de información utilizados por el sector público y las entidades privadas que les prestan servicios (cadena de suministro).

### Dimensiones de Seguridad y Categorías
Los sistemas se categorizan en función del impacto potencial ante un incidente de seguridad en cinco dimensiones:
- **Confidencialidad (C)**
- **Integridad (I)**
- **Trazabilidad (T)**
- **Autenticidad (A)**
- **Disponibilidad (D)**

Las categorías resultantes son: **BÁSICA**, **MEDIA** y **ALTA**.

## 2. Requisitos Exigibles para ENS Categoría Alta

### A. Marco Operacional y Control de Acceso (op.acc)
- **Principio de Mínimo Privilegio (op.acc.1):** Los usuarios y procesos solo tendrán acceso a los recursos y funciones estrictamente necesarios para su desempeño laboral.
- **Autenticación Multifactor Reforzada (op.acc.2):** Para acceso a sistemas ENS Alta, es obligatoria la autenticación multifactor (MFA) basada en factores independientes y tokens criptográficos resistentes al phishing (ej. FIDO2 / WebAuthn, tarjetas inteligentes criptográficas).
- **Segregación de Funciones:** Separación estricta entre administradores de sistemas, operadores, desarrolladores y responsables de seguridad.

### B. Registro de Actividad y Trazabilidad Inmutable (op.exp.8)
- Registro cronológico exhaustivo de todos los eventos relevantes de seguridad (accesos, modificaciones de privilegios, ejecuciones anómalas).
- Sincronización horaria obligatoria mediante servidores NTP autenticados y seguros (Nivel de estrato certificado).
- Protección inmutable y sellado de tiempo de las trazas de auditoría (logs WORM / Append-only) con hashes SHA-256 para garantizar el no repudio legal.

### C. Criptografía y Criptografía Post-Cuántica (PQC)
- Empleo exclusivo de mecanismos y algoritmos criptográficos homologados por el Centro Criptológico Nacional (CCN-STIC).
- Cumplimiento de estándares de módulos de seguridad FIPS 140-3 Nivel 3 o superior (HSM).
- Plan de transición hacia algoritmos de Criptografía Post-Cuántica (PQC) estandarizados por NIST:
  - FIPS 203 (ML-KEM para encapsulamiento de claves).
  - FIPS 204 (ML-DSA para firmas digitales basadas en retículos).
  - FIPS 205 (SLH-DSA para firmas digitales basadas en funciones hash sin estado).

### D. Continuidad del Servicio y Bunker Backups (op.pl)
- Planes de Continuidad de Negocio (BCP) y Recuperación ante Desastres (DRP) con pruebas periódicas documentadas.
- Copias de seguridad en bóveda aislada (Bunker Backups) con aislamiento físico o lógico (air-gap) y cifrado robusto para protección frente a ransomware destructivo.
