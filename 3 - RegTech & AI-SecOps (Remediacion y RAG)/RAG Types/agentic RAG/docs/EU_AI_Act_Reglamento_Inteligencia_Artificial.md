# Reglamento Europeo de Inteligencia Artificial (eu-ai-act-module - Reglamento UE 2024/1689)

## 1. Objeto y Enfoque Basado en Riesgo
El Reglamento (UE) 2024/1689 (eu-ai-act-module) establece un marco normativo armonizado para el desarrollo, comercialización y uso de sistemas de Inteligencia Artificial en la Unión Europea. La regulación clasifica los sistemas de IA en 4 categorías de riesgo:

1. **Riesgo Inaceptable (Sistemas Prohibidos):** Técnicas subliminales para distorsionar el comportamiento, explotación de vulnerabilidades de personas, puntuación social (social scoring), y sistemas de categorización biométrica que deduzcan opiniones políticas o religiosas.
2. **Alto Riesgo (High-Risk AI Systems):** Sistemas utilizados en infraestructuras críticas, gestión de empleo y recursos humanos, servicios esenciales públicos y privados (evaluación crediticia, scoring de seguros), aplicación de la ley, administración de justicia y ciberseguridad.
3. **Riesgo Específico de Transparencia:** Modelos de IA generativa y chatbots (deben informar al usuario que está interactuando con una IA y etiquetar los contenidos sintéticos / deepfakes).
4. **Riesgo Mínimo o Nulo:** Filtros de spam, videojuegos habilitados con IA (libres de obligaciones regulatorias adicionales).

## 2. Requisitos de Cumplimiento para Sistemas de IA de Alto Riesgo
Los proveedores y desplegadores de sistemas de IA de alto riesgo deben cumplir obligatoriamente:
- **Sistema de Gestión de Riesgos:** Proceso continuo, iterativo y documentado a lo largo de todo el ciclo de vida del sistema.
- **Gobernanza y Calidad de los Datos:** Conjuntos de datos de entrenamiento, validación y prueba libres de sesgos, representativos y trazables.
- **Documentación Técnica y Linaje SHA-256:** Documentación detallada previa a la puesta en servicio y registro automático de eventos (logging inmutable para trazabilidad).
- **Transparencia y Suministro de Información:** Instrucciones de uso claras, especificaciones sobre capacidades y limitaciones técnicas del sistema.
- **Supervisión Humana (Human-in-the-Loop / Human-on-the-Loop):** Diseño que permita a personas físicas supervisar, intervenir o detener el sistema de IA en cualquier momento.
- **Precisión, Solidez y Ciberseguridad:** Resiliencia frente a ataques adversarios (data poisoning, prompt injection, jailbreaking) y control estricto de alucinaciones mediante arquitecturas RAG fundamentadas en hechos (Groundedness y Faithfulness).
