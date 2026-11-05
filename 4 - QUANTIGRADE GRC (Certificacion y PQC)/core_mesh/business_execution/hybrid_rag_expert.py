"""Quantigrade GCR - HybridRAG 360° Regulatory Expert Engine.

Combines directed Knowledge Graph traversal (GraphRAG via BFS expansion)
and lexical entity matching across European, Spanish, and Global regulatory frameworks.
Reuses the curated knowledge graph from AUDITORIAS/NUEVO ORDEN/4_AI_AND_RAG_GOVERNANCE/Hybrid RAG/grafos.json.
100% deterministic, zero Docker, stdlib-native execution.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, Any, List, Set, Optional

DEFAULT_GRAFO_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "grafos.json"

class HybridRAGExpert:
    """Enterprise 360° Hybrid Regulatory RAG engine integrating Knowledge Graphs with lexical context."""

    REGULATORY_AUTHORITIES = {
        "DORA": "EBA / EIOPA / ESMA (Supervisión Europea del Sector Financiero)",
        "NIS2": "INCIBE-CERT / CCN-CERT (Equipo de Respuesta a Incidentes de Seguridad)",
        "ENS": "CCN (Centro Criptológico Nacional - Esquema Nacional de Seguridad)",
        "RGPD": "AEPD (Agencia Española de Protección de Datos) / EDPB",
        "AI ACT": "Oficina Europea de IA / AESIA (Agencia Española de Supervisión de IA)",
        "CRA": "ENISA (Agencia de Ciberseguridad de la Unión Europea)",
        "DATA ACT": "Comisión Europea / Autoridades Nacionales de Datos",
        "EIDAS": "Secretaría de Estado de Telecomunicaciones e Infraestructuras Digitales",
        "PQC": "NIST (FIPS 203/204/205) / BSI / CCN-STIC 807",
        "ISO27001": "AENOR / Entidades de Certificación Acreditadas ENAC",
        "LPIC": "CNPIC (Centro Nacional de Protección de Infraestructuras Críticas)"
    }

    def __init__(self, grafo_path: Optional[str | Path] = None):
        self.grafo_path = Path(grafo_path) if grafo_path else DEFAULT_GRAFO_PATH
        self.graph: Dict[str, List[Dict[str, Any]]] = {}
        self.reverse_graph: Dict[str, List[Dict[str, Any]]] = {}
        self.entities: Set[str] = set()
        self.triplets: List[Dict[str, Any]] = []
        self._load_knowledge_graph()

    def _load_knowledge_graph(self) -> None:
        """Loads and indexes the directed graph from grafos.json if available."""
        if not self.grafo_path.exists():
            return

        try:
            with open(self.grafo_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            raw_triplets = data.get("triplets", [])
            self.triplets = raw_triplets

            for t in raw_triplets:
                head = str(t.get("head", "")).strip()
                tail = str(t.get("tail", "")).strip()
                rel = str(t.get("relation", "RELACIONADO_CON")).strip()
                meta = t.get("metadata", {})

                if not head or not tail:
                    continue

                head_norm = head.lower()
                tail_norm = tail.lower()
                self.entities.add(head_norm)
                self.entities.add(tail_norm)

                edge = {"target": tail, "target_norm": tail_norm, "relation": rel, "metadata": meta}
                self.graph.setdefault(head_norm, []).append(edge)

                rev_edge = {"target": head, "target_norm": head_norm, "relation": f"INVERSO_{rel}", "metadata": meta}
                self.reverse_graph.setdefault(tail_norm, []).append(rev_edge)
        except Exception:
            # Degraded graceful fallback
            pass

    def extract_query_entities(self, query: str) -> List[str]:
        """Extracts matched entities from query string."""
        q_norm = query.lower()
        matched = []
        # Check against known entities
        for ent in self.entities:
            if len(ent) >= 3 and re.search(r"\b" + re.escape(ent) + r"\b", q_norm):
                matched.append(ent)
        
        # Check common acronyms
        for acr in ["dora", "nis2", "rgpd", "gdpr", "ens", "ai act", "pqc", "cra", "fips 204", "mfa", "cisa"]:
            if acr in q_norm and acr not in matched:
                matched.append(acr)
        return matched

    def bfs_traverse(self, start_entities: List[str], depth: int = 1) -> List[Dict[str, Any]]:
        """Performs BFS graph expansion from matched seed entities."""
        visited_nodes: Set[str] = set()
        visited_edges: List[Dict[str, Any]] = []

        queue = [(ent, 0) for ent in start_entities]
        for ent in start_entities:
            visited_nodes.add(ent)

        while queue:
            current, d = queue.pop(0)
            if d >= depth:
                continue

            # Forward edges
            for edge in self.graph.get(current, []):
                visited_edges.append({
                    "head": current,
                    "relation": edge["relation"],
                    "tail": edge["target"],
                    "source": edge.get("metadata", {}).get("source_file", "Normativa GCR")
                })
                tgt_norm = edge["target_norm"]
                if tgt_norm not in visited_nodes:
                    visited_nodes.add(tgt_norm)
                    queue.append((tgt_norm, d + 1))

            # Reverse edges
            for edge in self.reverse_graph.get(current, []):
                visited_edges.append({
                    "head": edge["target"],
                    "relation": edge["relation"].replace("INVERSO_", ""),
                    "tail": current,
                    "source": edge.get("metadata", {}).get("source_file", "Normativa GCR")
                })
                tgt_norm = edge["target_norm"]
                if tgt_norm not in visited_nodes:
                    visited_nodes.add(tgt_norm)
                    queue.append((tgt_norm, d + 1))

        return visited_edges

    def query_regulatory_expert(self, query: str, top_k: int = 5) -> Dict[str, Any]:
        """Processes an audit or compliance query returning graph context, legal citations, and expert dictamen."""
        entities = self.extract_query_entities(query)
        subgraph_edges = self.bfs_traverse(entities, depth=1) if entities else []

        # Find supervisory authorities
        authorities = []
        q_upper = query.upper()
        for fw_key, auth in self.REGULATORY_AUTHORITIES.items():
            if fw_key in q_upper or any(fw_key.lower() in e for e in entities):
                authorities.append({"framework": fw_key, "authority": auth})

        # Synthesize legal citations
        citations = set()
        for edge in subgraph_edges[:top_k * 2]:
            src = edge.get("source")
            if src and src != "Normativa GCR":
                citations.add(src.replace(".md", "").replace("_", " "))

        # Build synthesized expert dictamen
        dictamen_parts = []
        if entities:
            dictamen_parts.append(f"Entidades normativas identificadas: {', '.join(e.upper() for e in entities)}.")
        if subgraph_edges:
            dictamen_parts.append(f"Relaciones del Knowledge Graph recuperadas ({len(subgraph_edges)} conexiones activas).")
            top_relations = [f"{e['head'].upper()} -[{e['relation']}]-> {e['tail']}" for e in subgraph_edges[:top_k]]
            dictamen_parts.append("Vínculos clave: " + " | ".join(top_relations))
        else:
            dictamen_parts.append("Consulta analizada bajo el marco pericial unificado de Quantigrade GCR.")

        return {
            "query": query,
            "entities_found": entities,
            "subgraph_triplets": subgraph_edges[:top_k],
            "total_subgraph_relations": len(subgraph_edges),
            "supervisory_authorities": authorities,
            "legal_sources": sorted(list(citations)),
            "expert_dictamen": " ".join(dictamen_parts),
            "graph_available": len(self.triplets) > 0
        }

    @property
    def stats(self) -> dict[str, Any]:
        """Returns summary statistics for the Knowledge Graph."""
        return {
            "total_entities": len(self.entities),
            "total_triplets": len(self.triplets),
            "total_authorities": len(self.REGULATORY_AUTHORITIES),
            "graph_available": len(self.triplets) > 0
        }

