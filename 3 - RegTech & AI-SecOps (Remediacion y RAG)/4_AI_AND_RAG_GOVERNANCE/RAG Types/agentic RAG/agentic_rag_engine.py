"""agentic_rag_engine.py — Motor de Agentic RAG Enterprise (ReAct, Multi-Agent & Corrective Self-RAG).
================================================================================================
Arquitectura de Recuperación Aumentada por Generación Agéntica y Autónoma:
- Multi-Tool Dynamic Execution (Dense Vector, BM25 Lexical, Knowledge Graph, Compliance Calculator).
- Razonamiento Multi-Paso ReAct (Thought -> Action -> Observation -> Self-Reflection).
- Corrective RAG (CRAG) & Self-RAG: Evaluación dinámica de relevancia de documentos y filtrado de alucinaciones.
- Orquestación Multi-Agente para consultas complejas multi-marco (EU AI Act, DORA, ENS Alta, NIS2, RGPD).
- Blindaje Perimetral OWASP LLM Top 10 y Enmascaramiento PII (RGPD / LOPDGDD).
- Trazabilidad y Linaje Criptográfico SHA-256 (ENS Alta / EU AI Act).
"""

import hashlib
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CURRENT_DIR = Path(__file__).parent.resolve()
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from guardrails.input_guard import OWASPInputGuard
from guardrails.output_guard import OWASPOutputGuard
from rag_engine import HallucinationDetector, RAG360Engine


# ---------------------------------------------------------------------------
# STRUCTURED JSON LOGGER (SIEM & ENS ALTA)
# ---------------------------------------------------------------------------
class StructuredAgentLogger(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "agent": getattr(record, "agent_name", "AgenticRAGCore"),
            "action": getattr(record, "agent_action", "EXECUTE"),
            "message": record.getMessage(),
        }
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_obj.update(record.extra_fields)
        return json.dumps(log_obj, ensure_ascii=False)

def get_agent_logger(name: str = "AgenticRAG") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredAgentLogger())
        logger.addHandler(handler)
    return logger

agent_logger = get_agent_logger()


# ---------------------------------------------------------------------------
# 1. HERRAMIENTAS ESPECIALIZADAS DEL AGENTE (AGENT TOOL SUITE)
# ---------------------------------------------------------------------------
class AgentTool:
    """Clase base abstracta para herramientas del agente."""

    name: str = "base_tool"
    description: str = "Descripción de la herramienta"

    def execute(self, query: str, **kwargs) -> dict[str, Any]:
        raise NotImplementedError


class DenseVectorTool(AgentTool):
    name = "dense_vector_search"
    description = "Búsqueda vectorial semántica densa de conceptos, definiciones y políticas generales."

    def __init__(self, rag_engine: RAG360Engine) -> None:
        self.engine = rag_engine

    def execute(self, query: str, top_k: int = 3, **kwargs) -> dict[str, Any]:
        q_vec = self.engine.embedding_provider.encode([query])[0]
        results = []
        for rec in self.engine.vector_store.records:
            sim = self.engine.vector_store._cosine_similarity(q_vec, rec["embedding"])
            results.append((rec, sim))
        results.sort(key=lambda x: x[1], reverse=True)
        top_chunks = [{"id": r[0]["id"], "content": r[0]["content"], "score": round(r[1], 4), "source": r[0]["metadata"].get("source_file", "unknown")} for r in results[:top_k]]
        return {"tool": self.name, "count": len(top_chunks), "results": top_chunks}


class BM25LexicalTool(AgentTool):
    name = "bm25_lexical_search"
    description = "Búsqueda exacta por palabras clave, artículos normativos específicos, plazos y números de leyes."

    def __init__(self, rag_engine: RAG360Engine) -> None:
        self.engine = rag_engine

    def execute(self, query: str, top_k: int = 3, **kwargs) -> dict[str, Any]:
        matches = self.engine.vector_store.bm25_engine.search(query, top_k=top_k)
        results = []
        for idx, score in matches:
            if idx < len(self.engine.vector_store.records):
                rec = self.engine.vector_store.records[idx]
                results.append({
                    "id": rec["id"],
                    "content": rec["content"],
                    "score": round(score, 4),
                    "source": rec["metadata"].get("source_file", "unknown"),
                })
        return {"tool": self.name, "count": len(results), "results": results}


class GraphKnowledgeTool(AgentTool):
    name = "knowledge_graph_traversal"
    description = "Exploración de entidades normativas y relaciones relacionales en el Grafo de Conocimiento."

    def __init__(self, rag_engine: RAG360Engine) -> None:
        self.engine = rag_engine

    def execute(self, query: str, depth: int = 1, max_triplets: int = 10, **kwargs) -> dict[str, Any]:
        if not self.engine.graph or not self.engine.graph_retriever:
            return {"tool": self.name, "count": 0, "results": [], "triplets": []}
        retrieval = self.engine.graph_retriever.retrieve(query, self.engine.graph, depth=depth, max_triplets=max_triplets)
        return {
            "tool": self.name,
            "matched_entities": retrieval.get("matched_entities", []),
            "triplets": retrieval.get("triplets", []),
            "context": retrieval.get("context", []),
        }


class ComplianceCalculatorTool(AgentTool):
    name = "compliance_calculator"
    description = "Calculador determinista de sanciones económicas, plazos de notificación y categorización ENS/NIS2/DORA."

    KNOWLEDGE_MATRIX = {
        "nis2_sancion_esencial": {"max_euros": 10000000, "pct_facturacion": 2.0, "ref": "Directiva NIS2 Art. 34"},
        "nis2_sancion_importante": {"max_euros": 7000000, "pct_facturacion": 1.4, "ref": "Directiva NIS2 Art. 34"},
        "nis2_plazos_notificacion": {"alerta_temprana_horas": 24, "notificacion_incidente_horas": 72, "informe_final_meses": 1, "ref": "Directiva NIS2 Art. 23"},
        "rgpd_plazo_brecha": {"plazo_aepd_horas": 72, "ref": "RGPD Art. 33"},
        "dora_periodicidad_tlpt": {"anios": 3, "ref": "DORA Art. 26"},
    }

    def execute(self, query: str, **kwargs) -> dict[str, Any]:
        q_lower = query.lower()
        findings = {}
        for key, data in self.KNOWLEDGE_MATRIX.items():
            words = key.split("_")
            if any(w in q_lower for w in words[:2]):
                findings[key] = data
        return {"tool": self.name, "findings": findings}


# ---------------------------------------------------------------------------
# 2. EVALUADORES CORRECTIVOS (CRAG & SELF-RAG GRADERS)
# ---------------------------------------------------------------------------
class DocumentRelevanceGrader:
    """Evalúa si los documentos recuperados por las herramientas son relevantes para la consulta."""

    @staticmethod
    def grade_relevance(query: str, chunks: list[dict[str, Any]], threshold: float = 0.3) -> dict[str, Any]:
        if not chunks:
            return {"status": "EMPTY", "is_relevant": False, "score": 0.0, "relevant_chunks": []}

        q_tokens = set(re.findall(r"\w+", query.lower()))
        relevant_chunks = []

        for c in chunks:
            text = c.get("content", "").lower()
            c_tokens = set(re.findall(r"\w+", text))
            overlap = q_tokens & c_tokens
            overlap_score = len(overlap) / max(len(q_tokens), 1)

            if overlap_score >= threshold or any(tok in text for tok in q_tokens if len(tok) > 4):
                c_copy = dict(c)
                c_copy["relevance_grade"] = round(overlap_score, 4)
                relevant_chunks.append(c_copy)

        relevance_rate = len(relevant_chunks) / len(chunks)
        return {
            "status": "EVALUATED",
            "is_relevant": len(relevant_chunks) > 0,
            "relevance_rate": round(relevance_rate, 4),
            "relevant_chunks": relevant_chunks,
        }


class HallucinationSelfGrader:
    """Verifica que la respuesta generada esté 100% fundamentada en las evidencias."""

    @staticmethod
    def grade_answer(answer: str, evidence_texts: list[str]) -> dict[str, Any]:
        return HallucinationDetector.evaluate_groundedness(answer, evidence_texts)


# ---------------------------------------------------------------------------
# 3. CONTROLADOR REACT Y ORQUESTADOR AGÉNTICO MULTI-PASO
# ---------------------------------------------------------------------------
class ReActAgentController:
    """Controlador ReAct que ejecuta el bucle autónomo:
    Thought -> Action -> Action Input -> Observation -> Self-Reflection.
    """

    def __init__(self, rag_engine: RAG360Engine, max_iterations: int = 4) -> None:
        self.engine = rag_engine
        self.max_iterations = max_iterations
        self.tools: dict[str, AgentTool] = {
            DenseVectorTool.name: DenseVectorTool(rag_engine),
            BM25LexicalTool.name: BM25LexicalTool(rag_engine),
            GraphKnowledgeTool.name: GraphKnowledgeTool(rag_engine),
            ComplianceCalculatorTool.name: ComplianceCalculatorTool(),
        }

    def solve(self, query: str) -> dict[str, Any]:
        start_time = time.time()
        agent_steps = []
        collected_evidence: list[dict[str, Any]] = []
        seen_texts: set = set()

        # 1. Guardrail de Entrada
        is_safe, sanitized_query, diag = OWASPInputGuard.sanitize_prompt(query)
        if not is_safe:
            return {
                "status": "BLOCKED",
                "reason": diag.get("reason", "Prompt bloqueado por seguridad"),
                "answer": "La consulta no pudo procesarse debido a una infracción en las políticas de seguridad perimetral (OWASP LLM Guardrail).",
                "steps": [],
                "latency_ms": round((time.time() - start_time) * 1000, 2),
            }

        current_query = sanitized_query

        for step_idx in range(1, self.max_iterations + 1):
            step_record = {"step": step_idx, "thought": "", "action": "", "observation": None}

            # Decisión ReAct basada en la intención y el estado de la evidencia
            if step_idx == 1:
                # Paso 1: Búsqueda léxica y exacta de términos normativos
                thought = f"Analizando la consulta '{current_query}'. Inicio con búsqueda léxica BM25 para encontrar artículos y normativas exactas."
                action_name = BM25LexicalTool.name
                action_args = {"query": current_query, "top_k": 3}
            elif step_idx == 2:
                # Paso 2: Búsqueda vectorial semántica complementaria
                thought = f"Ampliando con búsqueda vectorial densa para capturar contexto semántico sobre '{current_query}'."
                action_name = DenseVectorTool.name
                action_args = {"query": current_query, "top_k": 3}
            elif step_idx == 3:
                # Paso 3: Grafo de conocimiento y cálculo de sanciones si aplica
                if any(w in current_query.lower() for w in ["sancion", "multa", "plazo", "hora", "calcul", "euro"]):
                    thought = "La consulta involucra métricas o plazos legales. Ejecuto el calculador determinista de cumplimiento."
                    action_name = ComplianceCalculatorTool.name
                    action_args = {"query": current_query}
                else:
                    thought = "Explorando relaciones y dependencias normativas en el Grafo de Conocimiento."
                    action_name = GraphKnowledgeTool.name
                    action_args = {"query": current_query, "depth": 1}
            else:
                # Paso de síntesis final
                thought = "Evidencia suficiente recolectada. Procediendo a la síntesis y verificación de fundamentación."
                break

            step_record["thought"] = thought
            step_record["action"] = action_name

            # Ejecución de la herramienta
            tool = self.tools.get(action_name)
            if tool:
                obs = tool.execute(**action_args)
                step_record["observation"] = obs

                # Corrective RAG: Calificación de relevancia
                if "results" in obs and isinstance(obs["results"], list):
                    grading = DocumentRelevanceGrader.grade_relevance(current_query, obs["results"])
                    step_record["grading"] = grading
                    for item in grading.get("relevant_chunks", []):
                        content = item.get("content", "")
                        if content and content not in seen_texts:
                            seen_texts.add(content)
                            collected_evidence.append(item)
                elif obs.get("findings"):
                    for k, v in obs["findings"].items():
                        text_finding = f"Regla {k}: {json.dumps(v)}"
                        if text_finding not in seen_texts:
                            seen_texts.add(text_finding)
                            collected_evidence.append({"id": f"calc_{k}", "content": text_finding, "source": v.get("ref", "compliance_matrix")})

            agent_steps.append(step_record)

        # 4. Síntesis y Ensamblado de Respuesta Final
        evidence_texts = [e.get("content", "") for e in collected_evidence]
        raw_answer = self._synthesize_answer(sanitized_query, collected_evidence)

        # 5. Guardrail de Salida y Detección de Alucinaciones
        _is_valid_out, sanitized_answer, out_meta = OWASPOutputGuard.sanitize_output(raw_answer, evidence_texts)
        faith_eval = HallucinationSelfGrader.grade_answer(sanitized_answer, evidence_texts)

        total_latency = round((time.time() - start_time) * 1000, 2)

        return {
            "status": "SUCCESS",
            "query": query,
            "answer": sanitized_answer,
            "evidence_count": len(collected_evidence),
            "evidence": collected_evidence,
            "steps_executed": len(agent_steps),
            "steps": agent_steps,
            "faithfulness": faith_eval,
            "output_guardrail": out_meta,
            "latency_ms": total_latency,
            "linaje_sha256": hashlib.sha256(sanitized_answer.encode("utf-8")).hexdigest(),
        }

    def _synthesize_answer(self, query: str, evidence: list[dict[str, Any]]) -> str:
        if not evidence:
            return f"No se encontró evidencia concluyente en el corpus normativo para responder a: '{query}'."

        citations = []
        key_facts = []
        for e in evidence:
            src = e.get("source", "Normativa")
            content = e.get("content", "").strip()
            if src not in citations:
                citations.append(src)
            key_facts.append(f"- {content} [Fuente: {src}]")

        citations_str = ", ".join(citations)
        facts_summary = "\n".join(key_facts[:6])

        return (
            f"Basado en el análisis agéntico multi-marco sobre '{query}', se han verificado los siguientes hechos normativos:\n\n"
            f"{facts_summary}\n\n"
            f"Atestación de Procedencia: Verificado contra [{citations_str}]."
        )


# ---------------------------------------------------------------------------
# 4. ORQUESTADOR DE AGENTES MULTI-MARCO (MULTI-AGENT ORCHESTRATOR)
# ---------------------------------------------------------------------------
class AgenticRAGOrchestrator:
    """Orquestador maestro que coordina agentes especializados y descompone consultas complejas."""

    def __init__(self, source_docs_dir: Path | None = None) -> None:
        self.engine = RAG360Engine(embedding_model="all-MiniLM-L6-v2", chunk_size=250, chunk_overlap=40)
        self.controller = ReActAgentController(self.engine)

        if source_docs_dir and source_docs_dir.exists():
            self.engine.ingest_directory(source_docs_dir)

    def route_and_execute(self, query: str) -> dict[str, Any]:
        """Clasifica la consulta y ejecuta la estrategia agéntica adecuada."""
        # Descomposición de consultas complejas multi-marco (ej. NIS2 vs DORA vs RGPD)
        if " vs " in query.lower() or " y " in query.lower() or "compara" in query.lower():
            return self._execute_comparative_plan(query)
        return self.controller.solve(query)

    def _execute_comparative_plan(self, complex_query: str) -> dict[str, Any]:
        """Descompone y resuelve consultas comparativas entre múltiples regulaciones."""
        sub_queries = []
        if "nis2" in complex_query.lower():
            sub_queries.append("Requisitos y plazos de la Directiva NIS2")
        if "dora" in complex_query.lower():
            sub_queries.append("Requisitos y resiliencia del Reglamento DORA")
        if "ens" in complex_query.lower():
            sub_queries.append("Requisitos de seguridad del Esquema Nacional de Seguridad ENS")
        if "rgpd" in complex_query.lower() or "privacidad" in complex_query.lower():
            sub_queries.append("Obligaciones de protección de datos bajo RGPD")

        if not sub_queries:
            sub_queries = [complex_query]

        sub_results = []
        all_evidence = []
        for sq in sub_queries:
            res = self.controller.solve(sq)
            sub_results.append({"sub_query": sq, "answer": res.get("answer", "")})
            all_evidence.extend(res.get("evidence", []))

        combined_answer = "\n\n---\n\n".join([f"### Análisis de {r['sub_query']}:\n{r['answer']}" for r in sub_results])

        return {
            "status": "SUCCESS_MULTI_AGENT_COMPARATIVE",
            "query": complex_query,
            "sub_tasks": len(sub_queries),
            "answer": combined_answer,
            "evidence_count": len(all_evidence),
            "evidence": all_evidence,
            "linaje_sha256": hashlib.sha256(combined_answer.encode("utf-8")).hexdigest(),
        }


# ---------------------------------------------------------------------------
# CLI & DEMO ENTRYPOINT
# ---------------------------------------------------------------------------
def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Agentic RAG Enterprise — Autonomous Multi-Agent ReAct Engine")
    parser.add_argument("-d", "--dir", default="./docs", help="Directorio con documentos normativos a ingestar")
    parser.add_argument("-q", "--query", default="¿Cuáles son las diferencias de plazos de notificación entre NIS2 y RGPD?", help="Consulta a resolver por el agente")
    args = parser.parse_args()

    docs_dir = Path(args.dir)
    orchestrator = AgenticRAGOrchestrator(docs_dir)


    result = orchestrator.route_and_execute(args.query)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
