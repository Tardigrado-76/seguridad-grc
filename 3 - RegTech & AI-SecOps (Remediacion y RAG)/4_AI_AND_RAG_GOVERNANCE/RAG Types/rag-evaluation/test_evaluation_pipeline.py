"""test_evaluation_pipeline.py — Unit & Integration Tests for RAG Evaluation Engine.
================================================================================
Pruebas automatizadas de métricas de calidad RAG (Faithfulness, Relevance, Precision).
"""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).parent.resolve()
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from evaluate_rag import DEFAULT_GOLDEN_DATASET, RAGEvaluatorEngine, mock_rag_predict


def test_evaluator_initialization() -> None:
    evaluator = RAGEvaluatorEngine()
    assert evaluator.dataset == DEFAULT_GOLDEN_DATASET
    assert len(evaluator.dataset) == 4


def test_faithfulness_metric() -> None:
    evaluator = RAGEvaluatorEngine()
    contexts = [
        "El Artículo 12 de la EU AI Act obliga a los sistemas de IA de alto riesgo a registrar eventos automáticamente.",
    ]
    good_answer = "Los sistemas de alto riesgo deben registrar eventos automáticamente según el Artículo 12 de la EU AI Act."
    score = evaluator.calculate_faithfulness(good_answer, contexts)
    assert score >= 0.70

    irrelevant_answer = "La pizza con piña es originaria de Canadá y no de Italia."
    bad_score = evaluator.calculate_faithfulness(irrelevant_answer, contexts)
    assert bad_score < 0.30


def test_answer_relevance_metric() -> None:
    evaluator = RAGEvaluatorEngine()
    question = "¿Cuáles son los requisitos de registro de la EU AI Act?"
    answer = "El Artículo 12 exige registro automático de eventos (logging) y trazabilidad para auditoría técnica."
    keywords = ["artículo 12", "registro", "logging", "trazabilidad"]
    score = evaluator.calculate_answer_relevance(answer, question, keywords)
    assert score >= 0.75


def test_benchmark_suite_execution(tmp_path) -> None:
    evaluator = RAGEvaluatorEngine()
    report_file = tmp_path / "test_report.json"
    report = evaluator.run_benchmark_suite(mock_rag_predict, str(report_file))

    assert "quality_gate" in report
    assert report["total_benchmarks"] == 4
    assert report["passed_benchmarks"] >= 3
    assert report["quality_gate"] == "PASSED"
    assert report_file.exists()
