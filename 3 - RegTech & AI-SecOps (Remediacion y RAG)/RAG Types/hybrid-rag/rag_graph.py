import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rag_graph.py — Capa GraphRAG / Knowledge Graph del HybridRAG
============================================================
Implementa el componente de Grafo de Conocimiento (KG) del paper
"HybridRAG: Integrating Knowledge Graphs and Vector Retrieval Augmented
Generation for Efficient Information Extraction" (arXiv:2408.04948).

Arquitectura (según §2.2 / §4.1 del paper):
- Knowledge Extraction: detección de entidades (reconocimiento de entidades)
  y extracción de relaciones (tripletas) por documento/chunk.
- Knowledge Improvement: normalización de entidades, fusión de sinónimos y
  deduplicación de tripletas.
- GraphRAG retrieval (§4.3): matching de entidades de la consulta sobre el KG
  y expansión mediante DFS/BFS con profundidad limitada (depth=1).
- HybridRAG (§4.4): el contexto del grafo se concatena DESPUÉS del contexto
  vectorial, exactamente como indica el paper, para alimentar al generador.

100% local y determinista: extracción basada en patrones (sin dependencias
externas). Opcionalmente se puede habilitar una cadena LLM de dos niveles
(refinamiento + extracción de tripletas JSON) cuando OPENAI_API_KEY está
configurada, replicando la metodología del paper.
"""

import json
import re
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set

logger = logging.getLogger("RAG360Graph")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)

# ---------------------------------------------------------------------------
# 1. EXTRACCIÓN DE ENTIDADES (Knowledge Extraction)
# ---------------------------------------------------------------------------

# Patrones de entidad típicos de dominios normativos/técnicos (ES/EN)
# Acrónimos alfanuméricos: NIS2, DORA, FIPS 204, EBA/RTS, ML-DSA-87, FIDO2...
_ACRONYM_RE = re.compile(r"\b[A-Z]{2,}(?:\d+)?(?:[-\s/][A-Z]{2,}(?:\d+)?)*\b")
_REFERENCE_RE = re.compile(
    r"\b(?:RD|Ley|Reglamento|Directiva|Regulation|Directive|Standard|ISO|IEC|NIST|FIPS)\s*/?\s*"
    r"[A-Z]{0,6}\s*[\d/.\-]{2,}\b"
)
_PROPERTY_RE = re.compile(
    r"\b(?:[A-ZÁÉÍÓÚÑÜ][a-záéíóúñü]+(?:\s+(?:de|del|la|el|los|las|y|e|o|en|al|para|por|según|sobre|de|al|ante|bajo|con|desde|entre|hacia|hasta|mediante|según|sin|sobre|tras)\s+[A-ZÁÉÍÓÚÑÜ][a-záéíóúñü]+){0,3})"
)
_METRIC_RE = re.compile(
    r"\b\d+(?:[.,]\d+)?\s*(?:%|€|EUR|USD|GB|MB|ms|h|días|dias|horas|años|años)\b",
    re.IGNORECASE,
)
_NORM_CODE_RE = re.compile(
    r"\b(?:Art\.?|Anexo|Capítulo|Sección)\s*[\dIVX]+\b", re.IGNORECASE
)


class EntityExtractor:
    """Extracción determinista de entidades nombradas y relaciones (tripletas).

    Implementa la fase 'Knowledge Extraction' del paper sin requerir un LLM:
    - Entidades: acrónimos, referencias normativas, nombres propios, métricas.
    - Relaciones: verbos copulativos/regulatorios entre entidades de la misma
      oración + tripletas numéricas (entidad -- métrica).
    """

    _VERB_PATTERNS = [
        (re.compile(r"\bes\b|\bson\b|\bse define como\b|\bconsta de\b|\bcomprende\b|\bis\b|\bare\b|\bconsists of\b|\bcomprises\b", re.IGNORECASE), "ES_TIPO_DE"),
        (re.compile(r"\bestablece\b|\brequiere\b|\bexige\b|\bobliga a\b|\bdebe\b|\bdeberá\b|\bshall\b|\bmust\b|\brequires\b|\bestablishes\b|\bmandates\b", re.IGNORECASE), "REQUIERE"),
        (re.compile(r"\bprohíbe\b|\bprohibe\b|\bforbids\b|\bprohibits\b|\bpreviene\b|\bprevents\b", re.IGNORECASE), "PROHIBE"),
        (re.compile(r"\bpermite\b|\bpermits\b|\ballows\b|\bhabilita\b|\benables\b", re.IGNORECASE), "PERMITE"),
        (re.compile(r"\bgestiona\b|\bmanages\b|\bprocesa\b|\bprocesses\b|\bprotege\b|\bprotects\b|\bcontiene\b|\bcontains\b", re.IGNORECASE), "GESTIONA"),
        (re.compile(r"\brelacionado con\b|\brelated to\b|\bligado a\b|\blinked to\b|\basociado a\b|\bassociated with\b", re.IGNORECASE), "RELACIONADO_CON"),
    ]

    _ENTITY_TYPES = {
        "ACRONYM": _ACRONYM_RE,
        "REFERENCE": _REFERENCE_RE,
        "NORM_CODE": _NORM_CODE_RE,
        "PROPER_NOUN": _PROPERTY_RE,
        "METRIC": _METRIC_RE,
    }

    # Artículos/partículas que generan ruido como nombres propios aislados
    _STOPWORDS = {
        "el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "al", "y", "e", "o", "u",
        "para", "por", "en", "con", "es", "son", "que", "como", "se", "su", "sus", "a", "ante",
        "bajo", "cabe", "contra", "desde", "durante", "entre", "hacia", "hasta", "mediante", "según",
        "sobre", "tras", "todo", "toda", "todos", "todas", "cada", "este", "esta", "este", "estos", "estas"
    }

    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """Devuelve [{name, type, count}] con entidades únicas del texto."""
        if not text:
            return []
        counts: Dict[str, Dict[str, Any]] = {}
        for etype, pattern in self._ENTITY_TYPES.items():
            for match in pattern.finditer(text):
                name = match.group(0).strip()
                if len(name) < 2:
                    continue
                norm = self._normalize(name)
                # Filtro de ruido: nombres propios de un solo token que son partículas
                if etype == "PROPER_NOUN" and " " not in norm and norm in self._STOPWORDS:
                    continue
                entry = counts.get(norm)
                if entry is None:
                    counts[norm] = {"name": name, "type": etype, "count": 1}
                else:
                    counts[norm]["count"] += 1
        return sorted(counts.values(), key=lambda e: e["count"], reverse=True)

    @staticmethod
    def _normalize(name: str) -> str:
        return re.sub(r"\s+", " ", name).strip().lower()

    def extract_triplets(self, text: str, chunk_id: str, source_file: str) -> List[Dict[str, Any]]:
        """Extrae tripletas (head, relation, tail, metadata) del chunk.

        Estrategia (sin LLM, determinista):
        1. Entidades del chunk.
        2. Oración a oración: si hay entidad A y entidad B unidas por un verbo
           regulador, se crea la tripleta (A, VERBO, B).
        3. Tripleta numérica: (entidad, "TIENE_METRICA", metric) cuando una
           entidad y una métrica coexisten en la misma oración.
        4. Fallback: entidades que comparten oración se vinculan con
           RELACIONADO_CON.
        """
        triplets: List[Dict[str, Any]] = []
        entities = self.extract_entities(text)
        if not entities:
            return triplets

        seen: Set[Tuple[str, str, str]] = set()
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]

        for sent in sentences:
            sent_entities = [e for e in entities if self._normalize(e["name"]) in sent.lower() or e["name"] in sent]
            if len(sent_entities) < 1:
                continue

            # Verbo regulador entre pares de entidades
            relation = None
            for pattern, rel_name in self._VERB_PATTERNS:
                if pattern.search(sent):
                    relation = rel_name
                    break

            if relation and len(sent_entities) >= 2:
                for i in range(len(sent_entities) - 1):
                    head, tail = sent_entities[i], sent_entities[i + 1]
                    triplet = self._make_triplet(head["name"], relation, tail["name"], chunk_id, source_file, seen)
                    if triplet:
                        triplets.append(triplet)
            elif len(sent_entities) >= 2:
                for i in range(len(sent_entities) - 1):
                    head, tail = sent_entities[i], sent_entities[i + 1]
                    triplet = self._make_triplet(head["name"], "RELACIONADO_CON", tail["name"], chunk_id, source_file, seen)
                    if triplet:
                        triplets.append(triplet)

            # Tripleta numérica: entidad + métrica en la misma oración
            metrics = [e for e in sent_entities if e["type"] == "METRIC"]
            non_metrics = [e for e in sent_entities if e["type"] != "METRIC"]
            for ent in non_metrics:
                for met in metrics:
                    triplet = self._make_triplet(ent["name"], "TIENE_METRICA", met["name"], chunk_id, source_file, seen)
                    if triplet:
                        triplets.append(triplet)

        return triplets

    def _make_triplet(self, head: str, relation: str, tail: str, chunk_id: str,
                      source_file: str, seen: Set[Tuple[str, str, str]]) -> Optional[Dict[str, Any]]:
        head_n = self._normalize(head)
        tail_n = self._normalize(tail)
        if head_n == tail_n:
            return None
        key = (head_n, relation, tail_n)
        if key in seen:
            return None
        seen.add(key)
        return {
            "head": head,
            "head_norm": head_n,
            "relation": relation,
            "tail": tail,
            "tail_norm": tail_n,
            "metadata": {"chunk_id": chunk_id, "source_file": source_file},
        }


# ---------------------------------------------------------------------------
# 2. GRAFO DE CONOCIMIENTO (Knowledge Graph)
# ---------------------------------------------------------------------------
class KnowledgeGraph:
    """Grafo dirigido en memoria: nodos = entidades, aristas = relaciones.

    Persistencia JSON (portable, auditável). El paper usa pickle; aquí se usa
    JSON por trazabilidad (ENS Alta / EU AI Act) y compatibilidad CI/CD.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.triplets: List[Dict[str, Any]] = []
        self._adjacency: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        self._entity_chunks: Dict[str, Set[str]] = defaultdict(set)

    def add_triplet(self, triplet: Dict[str, Any]):
        head_norm = triplet["head_norm"]
        tail_norm = triplet["tail_norm"]
        chunk_id = triplet["metadata"].get("chunk_id", "")

        if head_norm not in self.nodes:
            self.nodes[head_norm] = {"name": triplet["head"], "types": set(), "count": 0}
        if tail_norm not in self.nodes:
            self.nodes[tail_norm] = {"name": triplet["tail"], "types": set(), "count": 0}

        self.nodes[head_norm]["count"] += 1
        self.nodes[tail_norm]["count"] += 1
        self._adjacency[head_norm].append((triplet["relation"], tail_norm))
        self._entity_chunks[head_norm].add(chunk_id)
        self._entity_chunks[tail_norm].add(chunk_id)
        self.triplets.append(triplet)

    def add_entities(self, entities: List[Dict[str, Any]], chunk_id: str):
        for ent in entities:
            norm = ent["name"].lower().strip()
            if norm not in self.nodes:
                self.nodes[norm] = {"name": ent["name"], "types": set(), "count": 0}
            self.nodes[norm]["types"].add(ent["type"])
            self.nodes[norm]["count"] += 1
            self._entity_chunks[norm].add(chunk_id)

    # -- Búsqueda ----------------------------------------------------------
    def match_entities(self, query: str) -> List[str]:
        """Entidades del grafo que aparecen en la consulta (exacto o token)."""
        q_lower = query.lower()
        q_tokens = set(re.findall(r"\w+", q_lower))
        matches = []
        for norm in self.nodes:
            name_lower = norm
            if name_lower in q_lower:
                matches.append((norm, 3.0))
                continue
            # Coincidencia por tokens: ej. "NIS2" en "Directiva NIS2"
            name_tokens = set(re.findall(r"\w+", name_lower))
            if name_tokens and q_tokens:
                overlap = name_tokens & q_tokens
                if overlap:
                    score = len(overlap) / max(len(name_tokens), 1)
                    if score >= 0.5:
                        matches.append((norm, score))
        matches.sort(key=lambda x: x[1], reverse=True)
        return [m[0] for m in matches]

    def retrieve_subgraph(self, matched: List[str], depth: int = 1,
                          max_triplets: int = 20) -> List[Dict[str, Any]]:
        """Expansión BFS con profundidad limitada (paper §4.3: DFS depth 1)."""
        if not matched:
            return []
        frontier = list(matched)
        visited = set(matched)
        collected: List[Dict[str, Any]] = []
        collected_ids: Set[str] = set()

        for _ in range(depth):
            next_frontier = []
            for node in frontier:
                for relation, tail in self._adjacency.get(node, []):
                    for triplet in self.triplets:
                        if triplet["head_norm"] == node and triplet["tail_norm"] == tail and triplet["relation"] == relation:
                            tid = f"{node}|{relation}|{tail}"
                            if tid not in collected_ids:
                                collected.append(triplet)
                                collected_ids.add(tid)
                            break
                    if tail not in visited:
                        visited.add(tail)
                        next_frontier.append(tail)
                    if len(collected) >= max_triplets:
                        return collected
            frontier = next_frontier
            if not frontier:
                break
        return collected

    # -- Estadísticas / persistencia ---------------------------------------
    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "entities": len(self.nodes),
            "triplets": len(self.triplets),
            "avg_relations_per_entity": round(
                sum(len(v) for v in self._adjacency.values()) / max(len(self.nodes), 1), 2
            ),
        }

    def save(self, path: Path):
        payload = {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stats": self.stats,
            "triplets": self.triplets,
            "entity_chunks": {k: sorted(v) for k, v in self._entity_chunks.items()},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        tmp.replace(path)

    def load(self, path: Path):
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        self.triplets = payload.get("triplets", [])
        self._entity_chunks = defaultdict(set, {k: set(v) for k, v in payload.get("entity_chunks", {}).items()})
        self.nodes = {}
        self._adjacency = defaultdict(list)
        for t in self.triplets:
            head_norm, tail_norm = t["head_norm"], t["tail_norm"]
            if head_norm not in self.nodes:
                self.nodes[head_norm] = {"name": t["head"], "types": set(), "count": 0}
            if tail_norm not in self.nodes:
                self.nodes[tail_norm] = {"name": t["tail"], "types": set(), "count": 0}
            self.nodes[head_norm]["count"] += 1
            self.nodes[tail_norm]["count"] += 1
            self._adjacency[head_norm].append((t["relation"], tail_norm))


# ---------------------------------------------------------------------------
# 3. RETRIEVER GRÁFICO (GraphRAG retrieval)
# ---------------------------------------------------------------------------
class GraphRetriever:
    """Recupera contexto estructurado del KG para una consulta.

    Devuelve:
    - matched_entities: nodos del grafo que casan con la consulta.
    - triplets: tripletas del subgrafo expandido (depth=1).
    - context: cadenas legibles "head [relation] tail (fuente: chunk)".
    """

    def retrieve(self, query: str, graph: KnowledgeGraph, depth: int = 1,
                 max_triplets: int = 20) -> Dict[str, Any]:
        matched = graph.match_entities(query)
        if not matched:
            return {"matched_entities": [], "triplets": [], "context": []}

        triplets = graph.retrieve_subgraph(matched, depth=depth, max_triplets=max_triplets)

        context = []
        for t in triplets:
            meta = t.get("metadata", {})
            src = meta.get("source_file", "unknown")
            context.append(f"{t['head']} --{t['relation']}--> {t['tail']} [{src}]")

        return {
            "matched_entities": matched[:10],
            "triplets": triplets,
            "context": context,
        }


# ---------------------------------------------------------------------------
# 4. EXTRACTOR LLM OPCIONAL (dos niveles, según paper §4.1)
# ---------------------------------------------------------------------------
class LLMTripletExtractor:
    """Cadena LLM de dos niveles (refinamiento + tripletas JSON).

    Replica la metodología del paper (tier 1: resumen abstracto del chunk;
    tier 2: extracción de tripletas). Solo se instancia si hay OPENAI_API_KEY.
    """

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.0):
        self.model = model
        self.temperature = temperature
        self._client = None
        try:
            from openai import OpenAI
            import os
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                self._client = OpenAI(api_key=api_key)
        except ImportError:
            logger.warning("openai no instalado; LLMTripletExtractor desactivado")

    @property
    def available(self) -> bool:
        return self._client is not None

    def extract_triplets(self, chunk_text: str, chunk_id: str, source_file: str) -> List[Dict[str, Any]]:
        if not self._client:
            return []
        try:
            system = (
                "Extrae tripletas (head, relation, tail) de conocimiento normativo/técnico del texto. "
                "Devuelve SOLO JSON: [{\"head\": ..., \"relation\": ..., \"tail\": ...}]. "
                "Usa entidades concisas (< 4 palabras). Incluye relaciones regulatorias y métricas."
            )
            resp = self._client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": chunk_text[:4000]},
                ],
            )
            raw = resp.choices[0].message.content or ""
            start = raw.find("[")
            end = raw.rfind("]")
            if start == -1 or end == -1:
                return []
            data = json.loads(raw[start:end + 1])
            triplets = []
            for item in data:
                head = str(item.get("head", "")).strip()
                relation = str(item.get("relation", "")).strip().upper()
                tail = str(item.get("tail", "")).strip()
                if head and relation and tail:
                    triplets.append({
                        "head": head,
                        "head_norm": EntityExtractor._normalize(head),
                        "relation": relation,
                        "tail": tail,
                        "tail_norm": EntityExtractor._normalize(tail),
                        "metadata": {"chunk_id": chunk_id, "source_file": source_file},
                    })
            return triplets
        except Exception as e:
            logger.error("Fallo LLMTripletExtractor: %s", e)
            return []


if __name__ == '__main__':
    # Production entry point
    pass
