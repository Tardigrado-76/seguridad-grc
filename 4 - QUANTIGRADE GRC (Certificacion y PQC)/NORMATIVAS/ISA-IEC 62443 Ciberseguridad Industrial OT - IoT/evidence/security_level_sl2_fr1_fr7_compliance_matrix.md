# MATRIZ DE CONFORMIDAD DE REQUISITOS FUNDAMENTALES (FR 1 A FR 7) - SECURITY LEVEL SL-2+

| Requisito Fundamental (IEC 62443-3-3) | Implementación Técnica en Planta / Hub | Nivel Alcanzado | Estado |
| :--- | :--- | :---: | :---: |
| **FR 1: Control de Identificación y Autenticación** | MFA centralizado con certificados PKI en DMZ OT | **SL-3** | **CONFORME** |
| **FR 2: Control de Uso** | Autorización RBAC en HMIs y control de sesiones de ingeniería | **SL-2** | **CONFORME** |
| **FR 3: Integridad del Sistema** | Firmas de firmware en PLCs y detección de cambios de código | **SL-3** | **CONFORME** |
| **FR 4: Confidencialidad de Datos** | Cifrado TLS 1.3 en comunicaciones SCADA-MES y repositorios | **SL-2** | **CONFORME** |
| **FR 5: Flujo de Datos Restringido** | Filtrado estricto por conductos y diodos de datos en zonas críticas | **SL-4** | **CONFORME** |
| **FR 6: Respuesta Oportuna a Eventos** | SIEM industrial con reglas de detección de anomalías OT 24/7 | **SL-3** | **CONFORME** |
| **FR 7: Disponibilidad de Recursos** | Redundancia PRP/HSR sin tiempo de conmutación | **SL-3** | **CONFORME** |
