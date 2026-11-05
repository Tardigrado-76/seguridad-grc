"""Quantigrade GCR - Integration Test Suite for scratch_grc Capabilities.

Covers 18 tests:
- BM25SearchEngine (exact lexical retrieval)
- ReciprocalRankFuser (RRF fusion)
- SemanticLRUCache (in-memory + dual mode fallback)
- DocumentRelevanceGrader (CRAG gate)
- HallucinationSelfGrader (Self-RAG gate & SHA-256 lineage)
- AgenticRAGOrchestrator (ReAct loop & state checkpointing)
- ISOSOCComplianceMapper (ISO 27001 Annex A + SOC 2 TSC)
"""

from __future__ import annotations

import json
import time
import unittest
from pathlib import Path

from core_mesh.operational.hybrid_rag_enhancements import (
    BM25SearchEngine,
    ReciprocalRankFuser,
    SemanticLRUCache,
    tokenize,
    cosine_similarity,
)
from core_mesh.operational.hallucination_faithfulness_guard import (
    DocumentRelevanceGrader,
    HallucinationSelfGrader,
    extract_keywords,
    split_into_claims,
)
from core_mesh.operational.agentic_rag_orchestrator import (
    AgenticRAGOrchestrator,
    DEFAULT_REGULATORY_CORPUS,
)
from core_mesh.operational.iso_soc2_compliance_mapper import (
    ISOSOCComplianceMapper,
    TAXONOMY_MAP,
)


class TestScratchGRCIntegration(unittest.TestCase):
    """18 Test cases verifying full scratch_grc capabilities integrated into Quantigrade GCR."""

    # ==================== 1. BM25 Search Engine ====================

    def test_01_bm25_indexing_and_scoring(self) -> None:
        corpus = [
            {"id": "doc1", "content": "Directiva NIS2 exige alerta temprana en 24 horas para incidentes significativos."},
            {"id": "doc2", "content": "Reglamento DORA exige pruebas de resiliencia operativa TLPT en entidades financieras."},
            {"id": "doc3", "content": "Esquema Nacional de Seguridad ENS Categoría Alta requiere cifrado de datos."},
        ]
        engine = BM25SearchEngine(corpus)
        results = engine.search("alerta temprana NIS2", top_k=2)
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "doc1")
        self.assertIn("bm25_score", results[0])
        self.assertGreater(results[0]["bm25_score"], 0.0)

    def test_02_bm25_empty_query_and_corpus(self) -> None:
        empty_engine = BM25SearchEngine([])
        self.assertEqual(empty_engine.search("prueba"), [])
        populated_engine = BM25SearchEngine([{"id": "1", "content": "texto"}])
        self.assertEqual(populated_engine.search(""), [])

    def test_03_bm25_top_k_ordering(self) -> None:
        corpus = [
            {"id": "dora_1", "content": "DORA gestión de riesgos de TIC y pruebas periódicas."},
            {"id": "dora_2", "content": "DORA DORA resiliencia digital y notificación a EBA y autoridades."},
            {"id": "rgpd_1", "content": "RGPD protección de datos personales y privacidad."},
        ]
        engine = BM25SearchEngine(corpus)
        results = engine.search("DORA resiliencia", top_k=3)
        self.assertGreaterEqual(len(results), 2)
        # Verify descending score order
        scores = [r["bm25_score"] for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    # ==================== 2. Reciprocal Rank Fuser (RRF) ====================

    def test_04_rrf_fusing_dense_and_sparse(self) -> None:
        dense_hits = [
            {"id": "art_23", "title": "NIS2 Notificación", "dense_score": 0.95},
            {"id": "art_19", "title": "DORA Notificación", "dense_score": 0.85},
        ]
        sparse_hits = [
            {"id": "art_19", "title": "DORA Notificación", "bm25_score": 4.2},
            {"id": "art_23", "title": "NIS2 Notificación", "bm25_score": 3.8},
        ]
        fuser = ReciprocalRankFuser(k=60, dense_weight=0.6, sparse_weight=0.4)
        fused = fuser.fuse(dense_hits, sparse_hits, top_k=2)
        self.assertEqual(len(fused), 2)
        self.assertIn("rrf_score", fused[0])
        self.assertGreater(fused[0]["rrf_score"], fused[1]["rrf_score"])

    def test_05_rrf_disjoint_lists(self) -> None:
        dense_hits = [{"id": "doc_dense_1", "title": "Solo Dense"}]
        sparse_hits = [{"id": "doc_sparse_1", "title": "Solo Sparse"}]
        fuser = ReciprocalRankFuser(k=60)
        fused = fuser.fuse(dense_hits, sparse_hits, top_k=5)
        self.assertEqual(len(fused), 2)
        fused_ids = {f["id"] for f in fused}
        self.assertIn("doc_dense_1", fused_ids)
        self.assertIn("doc_sparse_1", fused_ids)

    # ==================== 3. Semantic LRU Cache ====================

    def test_06_cache_put_and_exact_hit(self) -> None:
        cache = SemanticLRUCache(capacity=50, similarity_threshold=0.90)
        query = "¿Cuáles son las sanciones de la Directiva NIS2?"
        response_payload = {"framework": "NIS2", "max_fine": "10M EUR"}
        cache.put(query, response_payload, ttl_s=300)

        hit = cache.get(query)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["framework"], "NIS2")
        self.assertTrue(hit["cache_hit"])
        self.assertEqual(cache.hits, 1)

    def test_07_cache_semantic_cosine_hit(self) -> None:
        cache = SemanticLRUCache(capacity=50, similarity_threshold=0.80)
        original_q = "plazos de notificacion de incidentes en DORA financiero"
        cache.put(original_q, {"answer": "Notificación inicial 4 horas"})

        # Similar query with high cosine similarity
        similar_q = "plazos de notificacion incidentes DORA financiero"
        hit = cache.get(similar_q)
        self.assertIsNotNone(hit)
        self.assertGreaterEqual(hit["semantic_similarity"], 0.80)
        self.assertEqual(hit["answer"], "Notificación inicial 4 horas")

    def test_08_cache_ttl_expiration(self) -> None:
        cache = SemanticLRUCache(capacity=10)
        cache.put("consulta rápida", {"data": "test"}, ttl_s=0)  # expires immediately
        time.sleep(0.01)
        res = cache.get("consulta rápida")
        self.assertIsNone(res)
        self.assertGreater(cache.misses, 0)

    def test_09_cache_dual_mode_fallback(self) -> None:
        # Pass non-existent redis_url to force fallback to native in-memory
        cache = SemanticLRUCache(use_redis=True, redis_url="redis://localhost:9999/0")
        self.assertEqual(cache.stats()["backend"], "native_memory")
        cache.put("consulta fallback", {"status": "ok"})
        self.assertIsNotNone(cache.get("consulta fallback"))

    # ==================== 4. Document Relevance Grader (CRAG) ====================

    def test_10_crag_relevant_document_decision(self) -> None:
        grader = DocumentRelevanceGrader(relevance_threshold=0.20)
        query = "requisitos de cifrado y criptografia en ENS Alta"
        doc = "El ENS Categoría Alta exige cifrado robusto y uso de criptografia acreditada por el CCN."
        res = grader.grade_document(query, doc)
        self.assertTrue(res["is_relevant"])
        self.assertGreater(res["score"], 0.20)
        self.assertIn("cifrado", res["matched_keywords"])

    def test_11_crag_irrelevant_document_fallback(self) -> None:
        grader = DocumentRelevanceGrader(relevance_threshold=0.30)
        query = "sanciones e indemnizaciones en transporte aéreo"
        doc = "La Directiva NIS2 regula la ciberseguridad en redes y sistemas de información esenciales."
        res = grader.grade_document(query, doc)
        self.assertFalse(res["is_relevant"])
        self.assertEqual(len(res["matched_keywords"]), 0)

    def test_12_crag_corpus_verdict_proceed(self) -> None:
        grader = DocumentRelevanceGrader(relevance_threshold=0.20)
        query = "notificación de incidentes graves DORA"
        corpus = [
            {"id": "1", "content": "DORA incidentes graves notificación inicial 4 horas a autoridades competentes."},
            {"id": "2", "content": "Plazos intermedios 72 horas para reporte de incidentes TIC en DORA."},
        ]
        verdict = grader.grade_corpus(query, corpus)
        self.assertEqual(verdict["action"], "PROCEED")
        self.assertEqual(verdict["relevant_count"], 2)

    # ==================== 5. Hallucination Self-Grader (Self-RAG) ====================

    def test_13_self_rag_grounded_response(self) -> None:
        grader = HallucinationSelfGrader(faithfulness_threshold=0.70)
        context = [
            "La Directiva NIS2 impone una sanción máxima de 10.000.000 EUR o 2% del volumen de negocio anual.",
            "Exige notificación de alerta temprana en un plazo de 24 horas tras el incidente."
        ]
        response = (
            "Bajo NIS2 la sanción máxima asciende a 10.000.000 EUR o 2% del volumen de negocio anual. "
            "Además, se requiere una alerta temprana en 24 horas."
        )
        eval_res = grader.evaluate_faithfulness(response, context)
        self.assertTrue(eval_res["is_grounded"])
        self.assertGreaterEqual(eval_res["faithfulness_ratio"], 0.70)
        self.assertEqual(eval_res["compliance_attestation"], "EU_AI_ACT_ART13_VERIFIED")

    def test_14_self_rag_hallucinated_claims_detection(self) -> None:
        grader = HallucinationSelfGrader(faithfulness_threshold=0.75)
        context = ["NIS2 exige alerta temprana en 24 horas."]
        hallucinated_response = (
            "El presidente de la Unión Europea firmó un decreto de prisión obligatoria para todos los "
            "programadores de bases de datos que no utilicen algoritmos cuánticos de Marte."
        )
        eval_res = grader.evaluate_faithfulness(hallucinated_response, context)
        self.assertFalse(eval_res["is_grounded"])
        self.assertGreater(eval_res["flagged_count"], 0)
        self.assertEqual(eval_res["compliance_attestation"], "REJECTED_UNGROUNDED")

    def test_15_self_rag_sha256_audit_lineage(self) -> None:
        grader = HallucinationSelfGrader()
        context = ["Prueba de contexto normativo DORA."]
        resp = "Respuesta basada en DORA normativo."
        eval_res = grader.evaluate_faithfulness(resp, context)
        self.assertIn("sha256_lineage", eval_res)
        self.assertEqual(len(eval_res["sha256_lineage"]), 64)

    # ==================== 6. Agentic RAG Orchestrator ====================

    def test_16_agentic_rag_full_react_cycle(self) -> None:
        orch = AgenticRAGOrchestrator(max_iterations=3)
        res = orch.run("¿Cuáles son los plazos de notificación y sanciones bajo NIS2?")
        self.assertIn("session_id", res)
        self.assertIn("response", res)
        self.assertIn("NIS2", res["response"])
        self.assertIn("24 horas", res["response"])
        self.assertGreater(res["faithfulness_ratio"], 0.50)
        self.assertEqual(len(res["sha256_audit_lineage"]), 64)
        self.assertEqual(res["backend_persistence"], "native_memory")

    def test_17_agentic_rag_checkpoint_state_retrieval(self) -> None:
        orch = AgenticRAGOrchestrator(max_iterations=2)
        res = orch.run("Requisitos de resiliencia operativa en DORA")
        sid = res["session_id"]
        saved_state = orch.get_session_state(sid)
        self.assertIsNotNone(saved_state)
        self.assertEqual(saved_state["status"], "COMPLETED")
        self.assertGreater(len(saved_state["thoughts"]), 0)

    # ==================== 7. ISO 27001 & SOC 2 Compliance Mapper ====================

    def test_18_iso_soc2_mapping_and_report_export(self) -> None:
        mapper = ISOSOCComplianceMapper()
        findings = [
            {"id": "F-01", "title": "Inyección SQL y vulnerabilidad en backend", "severity": "HIGH"},
            {"id": "F-02", "title": "Falta de autenticación multifactor MFA en acceso administrativo", "severity": "CRITICAL"},
            {"id": "F-03", "title": "Cifrado ausente en base de datos en reposo", "severity": "HIGH"},
        ]
        mapped = mapper.bulk_map(findings)
        self.assertEqual(len(mapped), 3)

        # Check ISO controls and SOC 2 criteria presence
        f1_iso = [c["id"] for c in mapped[0]["iso_27001_controls"]]
        self.assertTrue(any(c in ["A.8.8", "A.8.25", "A.8.28"] for c in f1_iso))

        f2_soc = [c["id"] for c in mapped[1]["soc_2_criteria"]]
        self.assertTrue(any("CC6." in c for c in f2_soc))

        # Check Markdown export
        md_report = mapper.export_report(mapped, fmt="md")
        self.assertIn("# Informe de Transposición Regulatoria", md_report)
        self.assertIn("| `F-01` |", md_report)
        self.assertIn("| `F-02` |", md_report)


if __name__ == "__main__":
    unittest.main()

