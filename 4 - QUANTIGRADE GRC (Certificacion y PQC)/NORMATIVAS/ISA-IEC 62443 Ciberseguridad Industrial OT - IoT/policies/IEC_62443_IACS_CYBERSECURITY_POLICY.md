# POLÍTICA DE CIBERSEGURIDAD INDUSTRIAL PARA SISTEMAS DE CONTROL Y AUTOMATIZACIÓN (ISA/IEC 62443)

## 1. Objeto y Alcance
Esta política define los requisitos de gobernanza, ingeniería de seguridad y operación técnica para Sistemas de Automatización y Control Industrial (IACS), redes de Tecnología Operativa (OT), sistemas SCADA, PLCs, RTUs y sensores IoT en terminales logísticas, puertos, aeropuertos y plantas de producción.

## 2. Marco Normativo
- **ISA/IEC 62443-2-1 / 2-3 / 2-4:** Programas de gestión de seguridad IACS y gestión de parches.
- **ISA/IEC 62443-3-2:** Evaluación de riesgos de seguridad y diseño de partición en Zonas y Conductos.
- **ISA/IEC 62443-3-3:** Requisitos de seguridad del sistema y Niveles de Seguridad (Security Levels SL 1 a SL 4).
- **ISA/IEC 62443-4-2:** Requisitos técnicos de seguridad para componentes IACS.

## 3. Requisitos Mandatorios de Seguridad Industrial
1. **Segmentación Estricta en Zonas y Conductos:** Todo activo industrial (PLC, HMI, servidor SCADA) debe pertenecer a una zona de seguridad homogénea. La comunicación inter-zona debe canalizarse exclusivamente a través de conductos protegidos por firewalls industriales de inspección profunda (DPI).
2. **Nivel de Seguridad Objetivo (SL-T 2 o superior):** Los sistemas críticos deben satisfacer los 7 Requisitos Fundamentales (FR 1: Control de Identificación/Autenticación, FR 2: Control de Uso, FR 3: Integridad del Sistema, FR 4: Confidencialidad de Datos, FR 5: Flujo de Datos Restringido, FR 6: Respuesta Oportuna a Eventos, FR 7: Disponibilidad de Recursos).
3. **Hardening y Aislamiento de Protocolos Legacy:** Se prohíbe la exposición directa a redes corporativas o a Internet de protocolos industriales no autenticados (Modbus TCP, DNP3, Ethernet/IP, Profinet).
4. **Gestión de Parches sin Afectación de Disponibilidad:** Planes de actualización controlada y pruebas en gemelo digital antes de cualquier despliegue en campo.
