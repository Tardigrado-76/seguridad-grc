# HybridRAG — Motor Enterprise RAG 360° (VectorRAG + GraphRAG)

Implementación production-ready de **HybridRAG** según el paper
[*HybridRAG: Integrating Knowledge Graphs and Vector Retrieval Augmented
Generation for Efficient Information Extraction*](https://arxiv.org/abs/2408.04948)
(BlackRock & NVIDIA).

## Arquitectura (mapeo directo al paper)

| Capa del paper | Implementación | Archivo |
| :--- | :--- | :--- |
| §2.1 VectorRAG | Embeddings densos (Cosine) + búsqueda esparsa BM25, fusión **RRF** | `rag_engine.py` → `HybridVectorStore` |
| §2.2 Knowledge Extraction | Extracción de entidades + tripletas (head, relation, tail, metadata) | `rag_graph.py` → `EntityExtractor` |
| §4.1 Two-tier LLM chain | Refinamiento + extracción de tripletas JSON (opcional, `OPENAI_API_KEY`) | `rag_graph.py` → `LLMTripletExtractor` |
| §4.3 GraphRAG retrieval | Matching de entidades de la consulta + expansión **BFS depth=1** | `rag_graph.py` → `GraphRetriever` |
| §4.4 HybridRAG fusion | Contexto vectorial **primero**, contexto del grafo **después** | `rag_engine.py` → `RAG360Engine.query` |
| §2.4 Evaluación | Faithfulness, Answer Relevance, Context Precision, Context Recall | `rag_engine.py` → `RAGEvaluator` |

## Componentes

- **`rag_engine.py`** — Motor principal: ingesta multi-formato, PII masking (RGPD), chunking por tokens, búsqueda híbrida Dense+BM25 con RRF, reranking Cross-Encoder, caché semántica, detector de alucinaciones, métricas y adaptadores LangChain/LlamaIndex.
- **`rag_graph.py`** — Capa Knowledge Graph: extracción de entidades (NIS2, FIDO2, DORA, FIPS 204...), tripletas normativas, grafo dirigido con persistencia JSON y retriever por expansión BFS.
- **`rag_assistant_gui.py`** — Interfaz desktop (Tkinter) que genera la Memoria Técnica RAG.
- **`rag_ingestion_pipeline.py` / `ingest_local.py`** — Pipelines batch asíncronos (OpenAI/Ollama/local) para vectorizar repositorios completos.

## Uso

```bash
# Instalación (embeddings locales)
pip install -r requirements.txt          # incluye sentence-transformers, rank-bm25

# Ingesta + consulta HybridRAG con persistencia del Knowledge Graph
python rag_engine.py -d ./docs -q "¿Qué exige NIS2 para incidentes?" --graph grafos.json

# Recargar un grafo persistido sin re-ingestar
python rag_engine.py -d ./docs -q "DORA TLPT" --graph grafos.json

# Extracción LLM de tripletas (dos niveles, requiere OPENAI_API_KEY)
python rag_engine.py -d ./docs -q "ENS Alta" --graph grafos.json --llm-triplets

# GUI desktop
python rag_assistant_gui.py
```

## Suite de pruebas (12 escenarios)

```bash
python test_rag_pipeline.py
```

Cubre: PII masking, ingesta multi-formato, búsqueda híbrida, reranking, caché,
detección de alucinaciones, métricas de recuperación, adaptadores,
construcción del Knowledge Graph, recuperación GraphRAG, fusión HybridRAG y
métricas del paper (Context Precision/Recall, Answer Relevance).

## Notas de producción

- **Determinista y soberano**: la capa de grafo usa solo stdlib (sin dependencias
  externas); los embeddings tienen fallback de hashing determinista si no hay
  GPU/modelo.
- **Persistencia JSON** (no pickle, como el paper) por trazabilidad ENS Alta / EU AI Act.
- El contexto del grafo se devuelve en `graph_context`/`graph_triplets` para que
  el generador lo concatene DESPUÉS del vectorial (orden del paper §4.4).
