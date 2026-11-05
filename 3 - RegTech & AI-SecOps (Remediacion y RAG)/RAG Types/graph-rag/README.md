# Motor Graph RAG Enterprise (Conocimiento Estructurado & Relacional)

[![Python 3.13](https://img.shields.io/badge/Python-3.13-blue.svg)]()
[![Graph Architecture](https://img.shields.io/badge/Architecture-Knowledge_Graph_%2B_Vector-orange.svg)]()
[![Compliance](https://img.shields.io/badge/Compliance-EU_AI_Act_|_DORA_|_ENS_Alta_|_NIS2_|_RGPD-purple.svg)]()
[![Security](https://img.shields.io/badge/Security-OWASP_LLM_Top_10_Guardrails-red.svg)]()

## 📌 Resumen Ejecutivo (C-Level & ROI)
El **Motor Graph RAG Enterprise** transforma el extenso corpus normativo (EU AI Act, DORA, NIS2) en un **Grafo de Conocimiento Fuertemente Tipado**. Esta arquitectura permite no solo la búsqueda de fragmentos aislados, sino la **comprensión profunda de las relaciones sistémicas** entre directivas, entidades, sanciones y obligaciones.

Mediante la resolución de correferencias y la indexación por comunidades jerárquicas, el sistema habilita dos modos de inferencia: **Local Search** (para consultas específicas sobre una entidad) y **Global Search** (para resúmenes ejecutivos y análisis holísticos a lo largo de toda la base de conocimiento).

### 💼 Ventajas Estratégicas y Retorno de Inversión (ROI)
- **Análisis de Impacto Sistémico:** Identifica cómo una vulnerabilidad o incumplimiento afecta en cascada a través de las dependencias organizacionales y normativas.
- **Reducción a Cero de Alucinaciones Relacionales:** Las afirmaciones del LLM están ancladas topológicamente a aristas verificables del Grafo de Conocimiento (ej. `[Entidad A] --(Reporta A)--> [Entidad B]`).
- **Consultas Multi-Nivel (Global RAG):** Permite responder preguntas amplias como "¿Cuáles son las principales tendencias de riesgo en el marco DORA?" resumiendo comunidades enteras de nodos en lugar de concatenar fragmentos inconexos.
- **Trazabilidad Absoluta:** Cada nodo y relación cuenta con linaje criptográfico SHA-256 hacia el documento normativo de origen, cumpliendo con ENS Categoría Alta.

---

## 🏗️ Arquitectura Graph RAG (Mermaid)

```mermaid
flowchart TD
    classDef input fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff;
    classDef graph fill:#b83280,stroke:#d53f8c,stroke-width:2px,color:#fff;
    classDef process fill:#2b6cb0,stroke:#4299e1,stroke-width:2px,color:#fff;
    classDef llm fill:#44337a,stroke:#805ad5,stroke-width:2px,color:#fff;
    classDef guard fill:#9b2c2c,stroke:#e53e3e,stroke-width:2px,color:#fff;

    User([Auditor / Ejecutivo]):::input --> InGuard[OWASP Input Guard\nFiltro Prompt Injections]:::guard
    
    InGuard --> QueryClassifier{Clasificador de Consulta\n¿Local o Global?}:::process
    
    QueryClassifier -- Consulta Específica --> LocalSearch[Local RAG Search\nBúsqueda de Vecindad (k-hop)]:::graph
    QueryClassifier -- Consulta Holística --> GlobalSearch[Global RAG Search\nResúmenes de Comunidad]:::graph

    subgraph Knowledge_Graph ["🕸️ Grafo de Conocimiento Estructurado"]
        EntityExt[Extracción de Entidades & Relaciones]:::process
        CoRef[Resolución de Correferencias]:::process
        Community[Detección de Comunidades\nAlgoritmo de Leiden]:::process
        
        EntityExt --> CoRef --> Community
    end

    LocalSearch --> Context[Contexto Topológico]:::graph
    GlobalSearch --> Context

    Context --> LLMInference[LLM Inference Engine]:::llm
    
    LLMInference --> OutGuard[OWASP Output Guard\nValidación de Aristas y PII]:::guard
    OutGuard --> FinalResp[Respuesta Basada en Grafo\ncon Trazabilidad SHA-256]:::input
```

---

## 📊 Matriz de Capacidades Técnicas y Cumplimiento

| Módulo / Capacidad | Componente Técnico | Propósito y Garantía de Seguridad | Marco Regulatorio |
| :--- | :--- | :--- | :--- |
| **Extracción de Nodos** | `EntityExtractor` | Identificación de normativas, roles, sistemas y sanciones. | General |
| **Relaciones (Aristas)** | `RelationMapper` | Mapeo tipado (ej. *sanciona*, *supervisa*, *requiere*). | General |
| **Agrupación Jerárquica** | `LeidenAlgorithm` | Detección de comunidades para Global RAG. | Rendimiento |
| **Resolución de Referencias**| `CoReferenceResolver`| Desambiguación de pronombres hacia entidades canónicas. | Precisión |
| **Búsqueda Local** | `LocalRAGSearch` | Exploración de vecindad k-hop para una entidad específica. | DORA / ENS |
| **Búsqueda Global** | `GlobalRAGSearch` | Map-Reduce sobre resúmenes de comunidades semánticas. | EU AI Act |
| **Prevención Inyección** | `OWASPInputGuard` | Bloqueo de manipulación de consultas de grafo (Cypher Injection). | OWASP LLM |
| **Atestación Topológica**| `GraphOutputGuard` | Verificación de que la respuesta existe en las aristas del grafo. | ENS Alta |

---

## 🚀 Guía de Inicio Rápido

### 1. Ingestión y Construcción del Grafo
```bash
# Procesa el corpus y extrae entidades, relaciones y comunidades
python ingest_graph.py -d ./docs --output grafos.json
```

### 2. Inferencia y Consultas
```bash
# Consulta Local (Específica)
python rag_graph.py -q "¿Qué obligaciones tiene un Proveedor de Servicios Esenciales según NIS2?" --mode local

# Consulta Global (Holística)
python rag_graph.py -q "Resume las diferencias principales en gestión de incidentes entre DORA y NIS2" --mode global
```

---

## 📚 Estructura de Directorios

```text
graph-rag/
├── docs/                               # Corpus normativo origen
├── guardrails/                         # Filtros de seguridad OWASP
├── rag_graph.py                        # Motor de Inferencia GraphRAG (Local/Global)
├── ingest_local.py                     # Extractor de grafos de conocimiento
├── grafos.json                         # Grafo exportado con entidades y relaciones
├── tests/                              # Pruebas funcionales de topología
├── Dockerfile                          # Despliegue seguro
└── README.md                           # Documentación C-Level
```
