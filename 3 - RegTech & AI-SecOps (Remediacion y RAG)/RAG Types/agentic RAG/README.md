# Motor Agentic RAG Enterprise (ReAct, Multi-Agent & Corrective Self-RAG)

[![Python 3.13](https://img.shields.io/badge/Python-3.13-blue.svg)]()
[![Agent Architecture](https://img.shields.io/badge/Architecture-ReAct_%2B_Multi--Agent-orange.svg)]()
[![Corrective RAG](https://img.shields.io/badge/CRAG-Self--RAG_Grading-green.svg)]()
[![Compliance](https://img.shields.io/badge/Compliance-EU_AI_Act_|_DORA_|_ENS_Alta_|_NIS2_|_RGPD-purple.svg)]()
[![Security](https://img.shields.io/badge/Security-OWASP_LLM_Top_10_Guardrails-red.svg)]()
[![Tests](https://img.shields.io/badge/Tests-7%2F7_Passed_100%25-success.svg)]()

## 📌 Resumen Ejecutivo (C-Level & ROI)
El **Motor Agentic RAG Enterprise** representa la cúspide evolutiva de los sistemas de recuperación aumentada por generación. A diferencia de los modelos RAG tradicionales (estáticos y pasivos), este sistema dota al pipeline de **autonomía de decisión, razonamiento multi-paso (ReAct) y autocorrección activa (Corrective Self-RAG)**.

El agente actúa como un auditor inteligente que formula hipótesis, selecciona dinámicamente herramientas especializadas (*Dense Vector, BM25 Lexical, Knowledge Graph, Compliance Calculator*), califica la relevancia de la evidencia recolectada y verifica la ausencia de alucinaciones antes de emitir un dictamen legalmente vinculante con linaje criptográfico **SHA-256**.

### 💼 Ventajas Estratégicas y Retorno de Inversión (ROI)
- **Resolución Autónoma de Consultas Multi-Marco:** Capacidad para desglosar consultas comparativas complejas (ej. *NIS2 vs DORA vs RGPD*) en sub-tareas atómicas coordinadas por un Orquestador Multi-Agente.
- **Autocorrección y Filtro de Evidencia Irrelevante (CRAG):** El *Document Relevance Grader* evalúa cada fragmento recuperado. Si la evidencia es insuficiente, el agente reformula la búsqueda o consulta el Grafo de Conocimiento automáticamente.
- **Cero Alucinaciones con Verificación Self-RAG:** La respuesta final es auditada por el *Hallucination Self-Grader* contra los hechos comprobados antes de ser emitida.
- **Blindaje Perimetral y Protección de PII:** Integración nativa con **OWASP LLM Top 10 Guardrails** para neutralizar *Prompt Injections* y sanitizar datos sensibles bajo **RGPD/LOPDGDD**.

---

## 🏗️ Arquitectura Agéntica ReAct y Multi-Agente (Mermaid)

```mermaid
flowchart TD
    classDef input fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff;
    classDef agent fill:#dd6b20,stroke:#ed8936,stroke-width:2px,color:#fff;
    classDef tool fill:#2b6cb0,stroke:#4299e1,stroke-width:2px,color:#fff;
    classDef crag fill:#2f855a,stroke:#48bb78,stroke-width:2px,color:#fff;
    classDef guard fill:#9b2c2c,stroke:#e53e3e,stroke-width:2px,color:#fff;

    User([Auditor / Usuario]):::input --> InGuard[OWASP Input Guard\nPrompt Injection Firewall]:::guard
    
    InGuard --> Router[Multi-Agent Router & Planner\nDescomposición de Consultas]:::agent

    subgraph ReAct_Loop ["🔄 Bucle de Razonamiento Autónomo ReAct"]
        Router --> Thought[1. Thought: Razonamiento e Hipótesis]:::agent
        Thought --> Action[2. Action: Selección de Herramienta Especializada]:::agent
        
        subgraph Tool_Suite ["🛠️ Suite de Herramientas Agénticas"]
            Action --> T1[Dense Vector Tool\nall-MiniLM-L6-v2]:::tool
            Action --> T2[BM25 Lexical Tool\nBúsqueda Exacta de Artículos]:::tool
            Action --> T3[Knowledge Graph Tool\nExploración de Entidades y Relaciones]:::tool
            Action --> T4[Compliance Calculator Tool\nCálculo de Sanciones y Plazos]:::tool
        end

        T1 & T2 & T3 & T4 --> Obs[3. Observation: Resultados de Herramientas]:::tool
        Obs --> CRAG{4. CRAG Relevance Grader\n¿Evidencia Relevante?}:::crag
        
        CRAG -- No / Insuficiente --> Reform[Re-Plan & Reformular Consulta]:::agent
        Reform --> Thought
    end

    CRAG -- Sí --> Synthesizer[Synthesizer & Critic Agent\nConsolidación de Evidencias]:::agent
    Synthesizer --> SelfRAG{Self-RAG Hallucination Grader\n¿100% Fundamentado?}:::crag
    
    SelfRAG -- Alucinación --> Synthesizer
    SelfRAG -- Aprobado --> OutGuard[OWASP Output Guard\nSanitización PII y Validación Citas]:::guard
    
    OutGuard --> FinalOutput[Respuesta Auditada con Citas y Linaje SHA-256]:::input
```

---

## 🛠️ Suite de Herramientas del Agente

| Herramienta | Clase Python | Propósito Operativo | Tipo de Inferencia |
| :--- | :--- | :--- | :--- |
| **Búsqueda Densa** | `DenseVectorTool` | Recuperación semántica de conceptos, políticas y directivas generales. | Vector Coseno (384-dim) |
| **Búsqueda Léxica** | `BM25LexicalTool` | Búsqueda determinista de artículos específicos, números de leyes y códigos. | BM25 Okapi |
| **Grafo Relacional** | `GraphKnowledgeTool`| Exploración de dependencias y entidades normativas en `grafos.json`. | BFS / DFS Traversal |
| **Calculadora Legal** | `ComplianceCalculatorTool`| Determinación exacta de sanciones (NIS2: 10M€/2%) y plazos de notificación (24h/72h). | Matriz Determinista |
| **Evaluador CRAG** | `DocumentRelevanceGrader` | Calificación de relevancia de fragmentos recuperados para decidir si re-planificar. | Solapamiento Semántico |
| **Auditor Self-RAG** | `HallucinationSelfGrader` | Verificación de que la respuesta esté estrictamente respaldada por la evidencia. | Faithfulness Ratio |

---

## 🚀 Guía de Inicio Rápido

### 1. Instalación
```bash
pip install -r requirements.txt
```

### 2. Ejecución Agéntica Vía CLI
```bash
# Consulta multi-paso autónoma con ReAct
python agentic_rag_engine.py -q "¿Cuáles son los plazos de notificación y sanciones bajo NIS2?"

# Consulta comparativa multi-marco descompuesta automáticamente
python agentic_rag_engine.py -q "Compara las obligaciones de notificación entre NIS2, DORA y RGPD"
```

### 3. Ejecución de la Suite de Pruebas
```bash
pytest test_agentic_rag.py -v
```

---

## 📚 Estructura de Directorios

```text
agentic RAG/
├── docs/                               # Corpus normativo (EU AI Act, DORA, ENS, NIS2, RGPD)
├── guardrails/                         # Guardrails de seguridad perimetral OWASP
│   ├── __init__.py
│   ├── input_guard.py                  # Firewall contra Prompt Injections y Jailbreaks
│   └── output_guard.py                 # Sanitizador de fugas PII y validador de procedencia
├── tests/                              # Pruebas funcionales del sistema
├── agentic_rag_engine.py               # Motor Agéntico ReAct, Multi-Agent & Corrective RAG
├── rag_engine.py                       # Motor base RAG 360° (Dense + BM25 + Cross-Encoder)
├── rag_graph.py                        # Capa de Grafo de Conocimiento (GraphRAG)
├── grafos.json                         # Grafo de conocimiento persistido y estructurado
├── test_agentic_rag.py                 # Suite de 7 pruebas agénticas automatizadas (100% Pass)
├── Dockerfile                          # Despliegue en contenedor aislado
├── docker-compose.yml                  # Orquestación de contenedores
├── requirements.txt                    # Dependencias de producción
└── README.md                           # Documentación ejecutiva C-Level y técnica
```
