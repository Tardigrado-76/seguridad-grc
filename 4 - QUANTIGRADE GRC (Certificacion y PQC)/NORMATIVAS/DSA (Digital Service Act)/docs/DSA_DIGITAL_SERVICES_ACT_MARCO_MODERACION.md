# Marco de Cumplimiento Digital Services Act (Reglamento UE 2022/2065)
## Regulación sobre Servicios Digitales y Gobernanza de Contenidos

### 1. Ficha Oficial EUR-Lex
- **Enlace Oficial EUR-Lex**: [Regulation (EU) 2022/2065 en EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2065)
- **Número CELEX**: `32022R2065`
- **Título Oficial**: *Reglamento (UE) 2022/2065 del Parlamento Europeo y del Consejo, de 19 de octubre de 2022, relativo a un mercado único de servicios digitales y por el que se modifica la Directiva 2000/31/CE (Reglamento de Servicios Digitales).*
- **Publicación Oficial**: Diario Oficial de la Unión Europea (DO L 277, 27.10.2022, p. 1–102).
- **Entrada en Vigor**: 16 de noviembre de 2022.
- **Fecha de Aplicación Plena**: 17 de febrero de 2024 para todas las plataformas intermediarias en la Unión Europea.

---

### 2. Módulos y Arquitectura Técnica Alineada con EUR-Lex

| Componente Técnico | Archivo Fuente | Artículos EUR-Lex Cumplidos | Especificación Técnica Armonizada |
| :--- | :--- | :--- | :--- |
| **Notice & Action Engine** | `engines/dsa_illegal_content_moderation_engine.py` | **Capítulo III Sección 2 (Art. 16)**, **Sección 2 (Art. 17)**, **Sección 3 (Art. 20)** | Tramitación electrónica estandarizada de notificaciones de contenido ilícito (Art. 16). Generación automatizada de Exposición de Motivos (*Statement of Reasons* - Art. 17) para el repositorio de transparencia de la Comisión Europea (*DSA Transparency Database*). Sistema interno de resolución de reclamaciones con revisión humana garantizada (*HITL* - Art. 20). |
| **Transparency Reporting** | `engines/dsa_transparency_reporting_generator.py` | **Art. 15**, **Art. 24**, **Art. 27** | Informes periódicos semestrales de transparencia de moderación de contenidos (Art. 15 y 24). Auditoría de algoritmos y sistemas de recomendación (Art. 27), garantizando la disponibilidad de al menos una opción que no se base en la elaboración de perfiles de usuario. |
| **Dark Patterns & Minors Guard** | `engines/dsa_dark_patterns_and_minors_guard.py` | **Art. 25**, **Art. 28** | Auditoría y eliminación de patrones oscuros / diseños engañosos en interfaces de usuario (Art. 25: asimetría de botones, confirmaciones forzadas, casillas premarcadas). Salvaguarda estricta de la seguridad y privacidad de menores en línea con prohibición absoluta de publicidad comportamental perfilada (Art. 28). |
| **Evaluador Central GCR** | `evaluators/dsa.py` | Todos los Capítulos DSA | Motor de auditoría automatizada conforme a `BaseEvaluator` para scoring continuo y reporte ejecutivo. |
| **Dashboard / Consola** | `dashboards_apps/dsa_moderation_portal.py` | **Arts. 16, 17, 24, 27** | Interfaz Streamlit y CLI para monitorización de tickets de moderación, apelaciones y métricas de transparencia. |

---

### 3. Controles Auditados y Evidencias Conforme a EUR-Lex

1. **Art. 16 - Mecanismos de Notificación y Acción:**
   - Formularios accesibles para notificaciones suficientemente precisas y fundamentadas.
   - Acuse de recibo y toma de decisiones objetivas y no arbitrarias sin dilación indebida.
2. **Arts. 17 & 20 - Exposición de Motivos y Sistema Interno de Reclamaciones:**
   - Emisión obligatoria de la exposición de motivos indicando base legal o contractual y vías de recurso.
   - Revisión humana obligatoria (*Human-in-the-Loop*) de apelaciones en el plazo de 6 meses.
3. **Arts. 15, 24 & 27 - Informes de Transparencia y Sistemas de Recomendación:**
   - Divulgación obligatoria de los parámetros de clasificación algorítmica.
   - Disponibilidad de al menos una opción que no se base en la elaboración de perfiles de usuario.
4. **Arts. 25 & 28 - Prohibición de Patrones Oscuros y Protección de Menores:**
   - Supresión de confirmaciones forzadas (*confirmshaming*), casillas premarcadas o asimetrías de diseño.
   - Prohibición absoluta de publicidad comportamental dirigida a usuarios identificados como menores.

---

### 4. Mapeo Transversal con Normativas GCR
- **ISO/IEC 27001:2022**: A.5.10 (Uso aceptable), A.5.24 (Gestión de incidentes), A.8.28 (Seguridad en codificación).
- **SOC 2 Type II**: CC2.2 (Comunicación ética), CC6.1 (Control de accesos), CC7.3 (Evaluación de incidentes).
- **RGPD / LOPDGDD**: Art. 8 (Tratamiento de datos de menores), Art. 25 (Privacidad desde el diseño).
