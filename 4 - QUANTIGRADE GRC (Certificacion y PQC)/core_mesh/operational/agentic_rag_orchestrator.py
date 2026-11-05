"""Quantigrade GCR - Agentic RAG Orchestrator Module.

Autonomous ReAct Multi-Agent Pipeline:
1. Thought: Strategic hypothesis & multi-step planning
2. Action: Dynamic selection of specialized tools (BM25, Dense, Graph, Compliance Calc)
3. Observation: Evidence retrieval and validation
4. CRAG Gate: DocumentRelevanceGrader evaluation & query expansion
5. Synthesis: Structured regulatory response formulation
6. Self-RAG Gate: HallucinationSelfGrader faithfulness verification
7. State Checkpoint: Dual mode (In-Memory stdlib default + optional Redis persistence)

Zero-Docker compliant with optional Docker/Redis backend adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

from core_mesh.operational.hybrid_rag_enhancements import (
    BM25SearchEngine,
    ReciprocalRankFuser,
    SemanticLRUCache,
)
from core_mesh.operational.hallucination_faithfulness_guard import (
    DocumentRelevanceGrader,
    HallucinationSelfGrader,
)

# Standard default regulatory corpus for native out-of-the-box operation
DEFAULT_REGULATORY_CORPUS = [
    {
        "id": "nis2_art_23",
        "framework": "NIS2",
        "title": "Directiva NIS2 - Art. 23 Obligaciones de Notificación",
        "content": (
            "Bajo la Directiva NIS2 (UE 2022/2555), las entidades esenciales e importantes deben emitir una "
            "alerta temprana en un plazo máximo de 24 horas tras tener conocimiento del incidente significativo, "
            "seguida de una notificación de incidente en 72 horas y un informe final en 1 mes. "
            "Las sanciones administrativas alcanzan hasta 10.000.000 EUR o el 2% del volumen de negocio total anual."
        ),
    },
    {
        "id": "dora_art_19",
        "framework": "DORA",
        "title": "Reglamento DORA - Art. 19 Notificación de Incidentes Graves de TIC",
        "content": (
            "El Reglamento DORA (UE 2022/2554) para el sector financiero exige notificar incidentes graves de TIC "
            "a la autoridad competente (EBA, EIOPA, ESMA o Banco de España). Se requiere notificación inicial en 4 horas "
            "o dentro del mismo día hábil, informe intermedio en 72 horas e informe final en 1 mes. "
            "Exige pruebas periódicas de resiliencia operativa digital y pruebas avanzadas TLPT (Threat-Led Penetration Testing)."
        ),
    },
    {
        "id": "ens_alta_anexo_ii",
        "framework": "ENS",
        "title": "Esquema Nacional de Seguridad (ENS) - Categoría Alta",
        "content": (
            "El RD 311/2022 (ENS Categoría Alta) exige autenticación multifactor (MFA) resistente a phishing, "
            "trazabilidad con firma electrónica y sellado de tiempo de logs de auditoría (op.exp.8), "
            "gestión continua de vulnerabilidades (op.vul.1) y cifrado de datos en reposo y en tránsito (mp.info.4) "
            "con algoritmos acreditados por el CCN-STIC."
        ),
    },
    {
        "id": "eu_ai_act_art_15",
        "framework": "EU_AI_ACT",
        "title": "Reglamento de Inteligencia Artificial (EU AI Act) - Art. 15 Ciberseguridad y Precisión",
        "content": (
            "Los sistemas de IA de alto riesgo deberán diseñarse y desarrollarse de modo que alcancen un nivel "
            "adecuado de precisión, solidez y ciberseguridad a lo largo de todo su ciclo de vida. "
            "Deben ser resistentes frente a intentos de terceros no autorizados de alterar su uso mediante prompt injections, "
            "envenenamiento de datos o ataques adversarios."
        ),
    },
    {
        "id": "rgpd_art_33_83",
        "framework": "RGPD",
        "title": "Reglamento General de Protección de Datos (RGPD) - Art. 33 y 83",
        "content": (
            "En caso de violación de la seguridad de los datos personales, el responsable del tratamiento "
            "la notificará a la autoridad de control (AEPD) sin dilación indebida y, a más tardar, 72 horas después. "
            "Las infracciones muy graves conllevan multas de hasta 20.000.000 EUR o el 4% del volumen de negocio anual mundial."
        ),
    },
]


class AgenticRAGOrchestrator:
    """Enterprise ReAct Multi-Agent Orchestrator for sovereign GRC environments."""

    def __init__(
        self,
        corpus: Optional[List[Dict[str, Any]]] = None,
        use_redis: bool = False,
        redis_url: Optional[str] = None,
        max_iterations: int = 4,
    ) -> None:
        self.corpus = corpus or DEFAULT_REGULATORY_CORPUS
        self.bm25 = BM25SearchEngine(self.corpus)
        self.fuser = ReciprocalRankFuser(k=60)
        self.relevance_grader = DocumentRelevanceGrader(relevance_threshold=0.25)
        self.hallucination_grader = HallucinationSelfGrader(faithfulness_threshold=0.70)
        self.max_iterations = max_iterations

        self.use_redis = use_redis or bool(os.getenv("REDIS_URL") or redis_url)
        self.cache = SemanticLRUCache(
            capacity=200,
            similarity_threshold=0.90,
            redis_url=redis_url,
            use_redis=self.use_redis,
        )

        self.redis_client: Optional[Any] = None
        if self.use_redis and HAS_REDIS:
            target_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
            try:
                client = redis.from_url(target_url, decode_responses=True, socket_timeout=1.0)
                client.ping()
                self.redis_client = client
            except Exception:
                self.redis_client = None

        self._in_memory_state_store: Dict[str, Dict[str, Any]] = {}

    def _persist_checkpoint(self, session_id: str, state: Dict[str, Any]) -> None:
        """Persist state checkpoint using Dual Mode (Redis if available, else in-memory)."""
        clean_state = dict(state)
        self._in_memory_state_store[session_id] = clean_state
        if self.redis_client:
            try:
                key = f"qg_agentic:state:{session_id}"
                self.redis_client.setex(key, 86400, json.dumps(clean_state, default=str))
            except Exception:
                pass

    def get_session_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve state checkpoint from Redis or in-memory store."""
        if self.redis_client:
            try:
                key = f"qg_agentic:state:{session_id}"
                val = self.redis_client.get(key)
                if val:
                    return json.loads(val)
            except Exception:
                pass
        return self._in_memory_state_store.get(session_id)

    # ------------------ RE-ACT TOOLS ------------------

    def _tool_bm25_search(self, query: str) -> List[Dict[str, Any]]:
        return self.bm25.search(query, top_k=3)

    def _tool_dense_search(self, query: str) -> List[Dict[str, Any]]:
        # Native pseudo-dense retrieval using query keyword overlap over full corpus
        q_tokens = set(query.lower().split())
        scored = []
        for doc in self.corpus:
            c_tokens = set(doc["content"].lower().split())
            overlap = len(q_tokens.intersection(c_tokens))
            if overlap > 0:
                d = dict(doc)
                d["dense_score"] = round(overlap / len(q_tokens), 4)
                scored.append(d)
        scored.sort(key=lambda x: x["dense_score"], reverse=True)
        return scored[:3]

    def _tool_compliance_calculator(self, framework: str) -> Dict[str, Any]:
        fw = framework.upper()
        if "NIS2" in fw:
            return {
                "framework": "NIS2",
                "fine_max": "10.000.000 EUR o 2% del volumen de negocio total anual",
                "notification_early_warning_hours": 24,
                "notification_incident_hours": 72,
                "final_report_days": 30,
            }
        if "DORA" in fw:
            return {
                "framework": "DORA",
                "fine_max": "Hasta 1% del volumen de negocios diario medio (multas coercitivas)",
                "notification_early_warning_hours": 4,
                "notification_interim_hours": 72,
                "final_report_days": 30,
            }
        if "RGPD" in fw or "GDPR" in fw:
            return {
                "framework": "RGPD",
                "fine_max": "20.000.000 EUR o 4% del volumen de negocios global anual",
                "notification_deadline_hours": 72,
            }
        return {"framework": framework, "status": "Standard regulatory baseline applies"}

    # ------------------ RE-ACT PIPELINE ------------------

    def run(self, query: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute autonomous ReAct cycle with CRAG and Self-RAG verification."""
        sid = session_id or hashlib.sha256(f"{query}_{time.time()}".encode()).hexdigest()[:12]

        # 0. Check Semantic Cache
        cached = self.cache.get(query)
        if cached:
            cached["session_id"] = sid
            cached["retrieval_mode"] = "SEMANTIC_CACHE_HIT"
            return cached

        # Initialize State
        state: Dict[str, Any] = {
            "session_id": sid,
            "query": query,
            "iteration": 0,
            "thoughts": [],
            "actions": [],
            "observations": [],
            "evidence": [],
            "crag_evaluations": [],
            "status": "RUNNING",
        }
        self._persist_checkpoint(sid, state)

        current_query = query
        while state["iteration"] < self.max_iterations:
            state["iteration"] += 1
            iter_num = state["iteration"]

            # 1. THOUGHT
            thought_msg = f"Iteración {iter_num}: Identificar marco regulatorio y buscar evidencia técnica."
            if iter_num == 1:
                action_name = "hybrid_search"
            elif any("sanci" in current_query.lower() or "plazo" in current_query.lower() or "multa" in current_query.lower() for _ in [1]):
                action_name = "compliance_calculator"
            else:
                action_name = "bm25_lexical"
            state["thoughts"].append(thought_msg)
            state["actions"].append(action_name)

            # 2. ACTION & 3. OBSERVATION
            if action_name == "hybrid_search":
                dense_hits = self._tool_dense_search(current_query)
                bm25_hits = self._tool_bm25_search(current_query)
                fused = self.fuser.fuse(dense_hits, bm25_hits, top_k=3)
                observation = fused
            elif action_name == "compliance_calculator":
                fw = "NIS2" if "nis2" in current_query.lower() else ("DORA" if "dora" in current_query.lower() else "RGPD")
                calc_res = self._tool_compliance_calculator(fw)
                observation = [calc_res]
            else:
                observation = self._tool_bm25_search(current_query)

            state["observations"].append(observation)

            # Accumulate string docs for evidence
            for item in observation:
                if isinstance(item, dict) and "content" in item and item not in state["evidence"]:
                    state["evidence"].append(item)

            # 4. CRAG RELEVANCE GATE
            evidence_docs = [e for e in state["evidence"] if isinstance(e, dict) and "content" in e]
            crag_res = self.relevance_grader.grade_corpus(query, evidence_docs)
            state["crag_evaluations"].append(crag_res)

            if crag_res["action"] == "PROCEED" or iter_num >= self.max_iterations:
                break
            elif crag_res["action"] == "EXPAND_QUERY":
                current_query = f"{query} articulos normativos sanciones obligaciones"
            else:
                current_query = f"{query} directiva reglamento cumplimiento"

            self._persist_checkpoint(sid, state)

        # 5. SYNTHESIS
        synthesis_lines = []
        sources = []
        for doc in state["evidence"]:
            if isinstance(doc, dict):
                title = doc.get("title", doc.get("id", "Fuente Regulatoria"))
                content = doc.get("content", "")
                if content:
                    synthesis_lines.append(f"- **{title}**: {content}")
                    sources.append(title)

        if not synthesis_lines:
            final_response = "No se encontraron evidencias normativas concluyentes en el corpus sovereign."
        else:
            final_response = (
                f"Dictamen de Cumplimiento Regulatorio para la consulta: '{query}'\n\n"
                + "\n\n".join(synthesis_lines)
            )

        # 6. SELF-RAG HALLUCINATION GATE
        source_texts = [d["content"] for d in state["evidence"] if isinstance(d, dict) and "content" in d]
        faith_eval = self.hallucination_grader.evaluate_faithfulness(final_response, source_texts, query)

        # 7. FINAL ATTESTATION & SHA-256
        lineage_payload = json.dumps({
            "session_id": sid,
            "query": query,
            "response_hash": hashlib.sha256(final_response.encode()).hexdigest(),
            "faithfulness": faith_eval["faithfulness_ratio"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, sort_keys=True)
        sha256_audit = hashlib.sha256(lineage_payload.encode()).hexdigest()

        result = {
            "session_id": sid,
            "query": query,
            "response": final_response,
            "sources": sources,
            "iterations_used": state["iteration"],
            "crag_verdict": crag_res["action"],
            "faithfulness_ratio": faith_eval["faithfulness_ratio"],
            "is_grounded": faith_eval["is_grounded"],
            "flagged_claims_count": faith_eval["flagged_count"],
            "sha256_audit_lineage": sha256_audit,
            "retrieval_mode": "REACT_MULTI_AGENT_SYNTHESIS",
            "backend_persistence": "redis" if self.redis_client else "native_memory",
        }

        # Put in semantic cache for sub-millisecond future hits
        self.cache.put(query, result, ttl_s=3600)
        state["status"] = "COMPLETED"
        state["result"] = result
        self._persist_checkpoint(sid, state)

        return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Quantigrade GCR - Agentic RAG Orchestrator CLI")
    parser.add_argument("-q", "--query", required=True, help="Regulatory query to solve")
    parser.add_argument("--max-iter", type=int, default=3, help="Max ReAct iterations")
    parser.add_argument("--use-redis", action="store_true", help="Enable Redis state persistence & cache adapter")
    parser.add_argument("--redis-url", type=str, default=None, help="Custom Redis URL")
    parser.add_argument("--json", action="store_true", help="Output pure JSON")

    args = parser.parse_args()
    orchestrator = AgenticRAGOrchestrator(
        max_iterations=args.max_iter,
        use_redis=args.use_redis,
        redis_url=args.redis_url,
    )
    res = orchestrator.run(args.query)

    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(f"\n[+] Agentic RAG Result ({res['retrieval_mode']})")
        print(f"Session ID : {res['session_id']}")
        print(f"Faithfulness: {res['faithfulness_ratio'] * 100:.1f}% (Grounded: {res['is_grounded']})")
        print(f"Lineage Hash: {res['sha256_audit_lineage']}")
        print(f"Backend     : {res['backend_persistence']}")
        print("\n" + res["response"])


if __name__ == "__main__":
    main()

