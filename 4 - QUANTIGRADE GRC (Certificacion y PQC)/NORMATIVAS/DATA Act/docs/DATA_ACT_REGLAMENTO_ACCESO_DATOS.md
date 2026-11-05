# Marco de Cumplimiento EU Data Act (Reglamento UE 2023/2854)
## Normas Armonizadas para un Acceso Justo a los Datos y su Utilización

### 1. Ficha Oficial EUR-Lex
- **Enlace Oficial EUR-Lex**: [Regulation (EU) 2023/2854 en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R2854)
- **Número CELEX**: `32023R2854`
- **Título Oficial**: *Reglamento (UE) 2023/2854 del Parlamento Europeo y del Consejo, de 13 de diciembre de 2023, sobre normas armonizadas para un acceso justo a los datos y su utilización, y por el que se modifican el Reglamento (UE) 2017/2394 y la Directiva (UE) 2020/1828 (Reglamento de Datos).*
- **Publicación Oficial**: Diario Oficial de la Unión Europea (DO L, 2023/2854, 22.12.2023).
- **Entrada en Vigor**: 11 de enero de 2024.
- **Fecha de Aplicación General**: 12 de septiembre de 2025.
- **Régimen Transitorio Tarifas de Salida (Art. 29)**: Reducción gradual y abolición total de costes de cambio (*Zero Egress Fees*) a más tardar el 12 de enero de 2027.

---

### 2. Módulos y Arquitectura Técnica Alineada con EUR-Lex

| Componente Técnico | Archivo Fuente | Artículos EUR-Lex Cumplidos | Especificación Técnica Armonizada |
| :--- | :--- | :--- | :--- |
| **B2B Sharing Broker** | `engines/data_act_b2b_sharing_broker.py` | **Capítulo II (Arts. 3-7)**, **Capítulo III (Arts. 8-12)** | Intermediación de datos B2B/B2C bajo condiciones FRAND (*Fair, Reasonable and Non-Discriminatory*). Compensación no discriminatoria limitada a costes de recuperación para PYMES (Art. 9(2)). Protección técnica y contractual de secretos comerciales (Arts. 4(6) y 5(9)). |
| **Cloud Switching Orchestrator** | `engines/data_act_cloud_switching_orchestrator.py` | **Capítulo VI (Arts. 23-29)** | Facilitación de cambio entre servicios de tratamiento de datos (IaaS/PaaS/SaaS). Supresión de barreras contractuales, eliminación total de tarifas de salida de datos (*Zero Egress Fees* - Art. 29) y SLA de transición de mínimo 30 días (Art. 26). |
| **Smart Contract Guard** | `engines/data_act_smart_contract_guard.py` | **Capítulo VIII (Art. 36)** | Auditoría de requisitos esenciales para contratos inteligentes en intercambio de datos: función de interrupción/finalización segura (*kill switch* - Art. 36(1)(a)), control de acceso estricto (Art. 36(1)(b)) y protección de confidencialidad comercial (Art. 36(1)(c)). |
| **Evaluador Central GCR** | `evaluators/data_act.py` | Todos los Capítulos Data Act | Motor de auditoría automatizada conforme a `BaseEvaluator` para scoring continuo y reporte ejecutivo. |
| **Dashboard / Consola** | `dashboards_apps/data_act_exchange_dashboard.py` | **Arts. 3, 23, 29, 36** | Interfaz Streamlit y CLI para monitorización de acuerdos de intercambio y planes de migración multi-cloud. |

---

### 3. Controles Auditados y Evidencias Conforme a EUR-Lex

1. **Arts. 3-5 & 8-13 - Acceso Justo y Condiciones FRAND:**
   - Acceso inmediato, continuo y seguro a los datos de telemetría IoT y productos conectados sin coste adicional para el usuario.
   - Puesta a disposición de terceros a petición del usuario bajo condiciones contractuales no abusivas (Art. 13).
2. **Arts. 23-29 - Portabilidad de Datos y Fin de Cargos por Salida (Zero Egress):**
   - Prohibición de imponer cargos económicos por transferencia de datos salientes (*egress fees*) durante la migración a otro proveedor o a infraestructura local (*on-premise*).
   - Exportación de datos en formatos abiertos, estructurados y legibles por máquina (Parquet, JSON, OCI).
3. **Art. 36 - Requisitos Esenciales de Contratos Inteligentes:**
   - Verificación de mecanismos de parada de emergencia (*safe termination / pause*) ante fallos o litigios.
   - Preservación de la integridad y coherencia transaccional durante interrupciones.
4. **Arts. 27 & 32 - Protección Frente a Accesos Gubernamentales Extranjeros:**
   - Cifrado de extremo a extremo con custodia de claves exclusiva en la UE para neutralizar solicitudes extraterritoriales no fundamentadas en tratados internacionales (MLAT).

---

### 4. Mapeo Transversal con Normativas GCR
- **ISO/IEC 27001:2022**: A.5.10 (Uso legítimo de la información), A.8.12 (Prevención de fuga de datos), A.8.20 (Seguridad de redes).
- **SOC 2 Type II**: CC6.1 (Control de accesos), CC6.6 (Protección de datos en tránsito y reposo).
- **ENISA EUCS**: [OPS-12] Portabilidad y reversibilidad de servicios cloud.
