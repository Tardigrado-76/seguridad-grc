"""evaluate_rag.py — Continuous RAG Quality & LLMOps Evaluation Suite.
==================================================================
Framework de evaluación automatizada para arquitecturas RAG Enterprise (Hybrid, Graph, Agentic).
Mide métricas de calidad estándar de la industria (Ragas / DeepEval):
- Faithfulness (Fidelidad / Consistencia Fáctica)
- Answer Relevance (Relevancia de Respuesta)
- Context Precision (Precisión del Contexto Recuperado)
- Context Recall (Cobertura de Contexto)
- Hallucination Index (Tasa de Alucinación)

Cumplimiento: EU AI Act Art. 15 (Accuracy, Robustness & Cybersecurity), ISO/IEC 42001 (AI Quality Management)
"""

import json
import re
import sys
import time
from pathlib import Path
from typing import Any

CURRENT_DIR = Path(__file__).parent.resolve()
ROOT_DIR = CURRENT_DIR.parent.parent.resolve()
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

SHARED_TELEMETRY_DIR = ROOT_DIR / "shared-telemetry"
if str(SHARED_TELEMETRY_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_TELEMETRY_DIR))

try:
    from observability import LLMOpsTracer
except ImportError:
    LLMOpsTracer = None  # type: ignore


# ---------------------------------------------------------------------------
# STOPWORDS EN ESPAÑOL PARA TOKENIZACIÓN SEMÁNTICA
# ---------------------------------------------------------------------------
STOPWORDS_ES = {
    "de", "la", "el", "los", "las", "un", "una", "unos", "unas", "en", "para",
    "por", "con", "se", "y", "o", "que", "es", "son", "del", "al", "a", "su",
    "sus", "este", "esta", "estos", "estas", "como", "sobre", "entre", "sin",
    "cuales", "cuál", "qué",
}


# ---------------------------------------------------------------------------
# GOLDEN DATASET: BENCHMARKS REGULATORIOS (ENS, DORA, NIS2, EU AI ACT)
# ---------------------------------------------------------------------------
DEFAULT_GOLDEN_DATASET: list[dict[str, Any]] = [
    {
        "id": "BENCH-001",
        "framework": "EU AI Act",
        "question": "¿Cuáles son los requisitos de registro y trazabilidad para sistemas de IA de alto riesgo?",
        "ground_truth": "El Artículo 12 de la EU AI Act exige capacidades de registro automático de eventos (logging) a lo largo de todo el ciclo de vida para garantizar la trazabilidad de operaciones, detección de riesgos y auditoría técnica.",
        "expected_keywords": ["artículo 12", "registro", "trazabilidad", "alto riesgo", "logging", "auditoría"],
        "min_faithfulness": 0.70,
        "min_answer_relevance": 0.70,
    },
    {
        "id": "BENCH-002",
        "framework": "DORA",
        "question": "¿Qué plazos y protocolos establece DORA para la notificación de incidentes TIC graves?",
        "ground_truth": "DORA exige que las entidades financieras notifiquen los incidentes TIC mayores a la autoridad competente: notificación inicial en un plazo máximo de 4 horas o al final del día hábil, informe intermedio en 72 horas e informe final en 1 mes.",
        "expected_keywords": ["4 horas", "72 horas", "1 mes", "incidentes mayores", "autoridad competente", "dora"],
        "min_faithfulness": 0.70,
        "min_answer_relevance": 0.70,
    },
    {
        "id": "BENCH-003",
        "framework": "ENS Alta",
        "question": "¿Qué exigencias de cifrado e inmutabilidad impone el ENS en categoría Alta para la custodia de auditorías?",
        "ground_truth": "El Esquema Nacional de Seguridad (ENS) en categoría Alta (op.mon.1, op.exp.8) impone el uso de algoritmos criptográficos acreditados por el CCN-CERT, sellado de tiempo cualificado, inmutabilidad de registros y segregación estricta de funciones.",
        "expected_keywords": ["ens", "alta", "ccn-cert", "inmutabilidad", "sellado de tiempo", "op.mon.1"],
        "min_faithfulness": 0.70,
        "min_answer_relevance": 0.70,
    },
    {
        "id": "BENCH-004",
        "framework": "NIS2",
        "question": "¿Qué sanciones y responsabilidades directas establece NIS2 para la alta dirección?",
        "ground_truth": "La Directiva NIS2 (Art. 20) establece la responsabilidad personal directa de los órganos de dirección en la supervisión de medidas de ciberseguridad, con multas de hasta 10 millones de euros o el 2% del volumen de negocio anual global para entidades esenciales.",
        "expected_keywords": ["nis2", "responsabilidad personal", "alta dirección", "10 millones", "2%", "entidades esenciales"],
        "min_faithfulness": 0.70,
        "min_answer_relevance": 0.70,
    },
]


class RAGEvaluatorEngine:
    """Motor de Evaluación Continua de Calidad RAG y LLMOps.
    Calcula métricas matemáticas normalizadas [0.0 - 1.0].
    """

    def __init__(self, golden_dataset: list[dict[str, Any]] | None = None) -> None:
        self.dataset = golden_dataset or DEFAULT_GOLDEN_DATASET
        self.tracer = LLMOpsTracer.get_instance() if LLMOpsTracer else None

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Tokenizador léxico normalizado con filtrado de stopwords."""
        raw_tokens = re.findall(r"\b[a-záéíóúüñ0-9_]{2,}\b", text.lower())
        return [t for t in raw_tokens if t not in STOPWORDS_ES]

    def calculate_faithfulness(self, generated_answer: str, retrieved_contexts: list[str]) -> float:
        """Calcula la fidelidad (Faithfulness): Proporción de afirmaciones generadas
        que están estrictamente fundamentadas en los fragmentos de contexto recuperados.
        """
        if not retrieved_contexts:
            return 0.0

        answer_tokens = set(self._tokenize(generated_answer))
        if not answer_tokens:
            return 0.0

        context_combined = " ".join(retrieved_contexts)
        context_tokens = set(self._tokenize(context_combined))

        # Medir intersección de términos clave sustantivos
        overlap = answer_tokens.intersection(context_tokens)
        score = len(overlap) / len(answer_tokens)
        return round(min(1.0, max(0.0, score * 1.10)), 4)

    def calculate_answer_relevance(self, generated_answer: str, question: str, expected_keywords: list[str]) -> float:
        """Calcula la relevancia de la respuesta con respecto a la pregunta original
        y las palabras clave esperadas.
        """
        answer_tokens = set(self._tokenize(generated_answer))
        if not answer_tokens:
            return 0.0

        question_tokens = set(self._tokenize(question))
        keyword_tokens = {k.lower() for k in expected_keywords}

        kw_matches = sum(1 for kw in keyword_tokens if kw in generated_answer.lower())
        kw_score = kw_matches / max(1, len(keyword_tokens))

        q_overlap = len(answer_tokens.intersection(question_tokens)) / max(1, len(question_tokens))

        # Ponderación 70% cobertura de conceptos clave + 30% correlación de pregunta
        final_score = (0.7 * kw_score) + (0.3 * q_overlap)
        return round(min(1.0, max(0.0, final_score)), 4)

    def calculate_context_precision(self, retrieved_contexts: list[str], ground_truth: str) -> float:
        """Calcula la precisión del contexto: Qué porcentaje de los fragmentos recuperados
        son efectivamente relevantes para responder la verdad de referencia.
        """
        if not retrieved_contexts:
            return 0.0

        gt_tokens = set(self._tokenize(ground_truth))
        relevant_chunks = 0

        for ctx in retrieved_contexts:
            ctx_tokens = set(self._tokenize(ctx))
            overlap = len(ctx_tokens.intersection(gt_tokens))
            if overlap >= 2:  # Umbral de significancia
                relevant_chunks += 1

        return round(relevant_chunks / len(retrieved_contexts), 4)

    def calculate_context_recall(self, retrieved_contexts: list[str], ground_truth: str) -> float:
        """Calcula la exhaustividad del contexto: Qué proporción de los hechos de la
        ground_truth están presentes en el contexto recuperado.
        """
        if not retrieved_contexts:
            return 0.0

        gt_tokens = set(self._tokenize(ground_truth))
        if not gt_tokens:
            return 1.0

        context_combined = " ".join(retrieved_contexts)
        ctx_tokens = set(self._tokenize(context_combined))

        overlap = gt_tokens.intersection(ctx_tokens)
        return round(len(overlap) / len(gt_tokens), 4)

    def evaluate_sample(
        self,
        sample: dict[str, Any],
        generated_answer: str,
        retrieved_contexts: list[str],
        duration_sec: float = 0.0,
    ) -> dict[str, Any]:
        """Evalúa una consulta individual y genera reporte de métricas."""
        faithfulness = self.calculate_faithfulness(generated_answer, retrieved_contexts)
        relevance = self.calculate_answer_relevance(
            generated_answer, sample["question"], sample.get("expected_keywords", []),
        )
        precision = self.calculate_context_precision(retrieved_contexts, sample["ground_truth"])
        recall = self.calculate_context_recall(retrieved_contexts, sample["ground_truth"])
        hallucination_index = round(max(0.0, 1.0 - faithfulness), 4)

        # Criterio de Pase Individual
        passed = (
            faithfulness >= sample.get("min_faithfulness", 0.70) and
            relevance >= sample.get("min_answer_relevance", 0.70)
        )

        return {
            "id": sample["id"],
            "framework": sample["framework"],
            "question": sample["question"],
            "faithfulness": round(faithfulness, 4),
            "answer_relevance": round(relevance, 4),
            "context_precision": round(precision, 4),
            "context_recall": round(recall, 4),
            "hallucination_index": hallucination_index,
            "duration_sec": round(duration_sec, 3),
            "status": "PASS" if passed else "FAIL",
        }

    def run_benchmark_suite(
        self,
        rag_engine_fn: Any,
        output_report_path: str | None = None,
    ) -> dict[str, Any]:
        """Ejecuta la suite completa de evaluación sobre el motor RAG suministrado.
        rag_engine_fn debe recibir una pregunta y retornar: (answer: str, contexts: List[str]).
        """
        results: list[dict[str, Any]] = []
        start_time = time.time()

        for sample in self.dataset:
            t0 = time.time()
            try:
                answer, contexts = rag_engine_fn(sample["question"])
            except Exception as e:
                answer = f"Error executing RAG: {e}"
                contexts = []
            dur = time.time() - t0

            sample_eval = self.evaluate_sample(sample, answer, contexts, dur)
            results.append(sample_eval)

        total_time = time.time() - start_time
        num_samples = len(results)

        avg_faithfulness = sum(r["faithfulness"] for r in results) / num_samples
        avg_relevance = sum(r["answer_relevance"] for r in results) / num_samples
        avg_precision = sum(r["context_precision"] for r in results) / num_samples
        avg_recall = sum(r["context_recall"] for r in results) / num_samples
        avg_hallucination = sum(r["hallucination_index"] for r in results) / num_samples
        pass_count = sum(1 for r in results if r["status"] == "PASS")

        # Quality Gate General: 75% de muestras aprobadas y fidelidad promedio >= 0.70
        gate_passed = (pass_count / num_samples >= 0.75) and (avg_faithfulness >= 0.70)

        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_benchmarks": num_samples,
            "passed_benchmarks": pass_count,
            "failed_benchmarks": num_samples - pass_count,
            "success_rate": round(pass_count / num_samples, 4),
            "quality_gate": "PASSED" if gate_passed else "FAILED",
            "aggregate_metrics": {
                "avg_faithfulness": round(avg_faithfulness, 4),
                "avg_answer_relevance": round(avg_relevance, 4),
                "avg_context_precision": round(avg_precision, 4),
                "avg_context_recall": round(avg_recall, 4),
                "avg_hallucination_index": round(avg_hallucination, 4),
                "total_evaluation_time_sec": round(total_time, 2),
            },
            "detailed_results": results,
        }

        if output_report_path:
            out_file = Path(output_report_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

        return report


def mock_rag_predict(question: str) -> tuple[str, list[str]]:
    """Función de predicción sintética para testing y CI/CD."""
    q_lower = question.lower()

    if "ai act" in q_lower or "alto riesgo" in q_lower:
        contexts = [
            "El Artículo 12 de la EU AI Act exige capacidades de registro automático de eventos (logging) a lo largo de todo el ciclo de vida para garantizar la trazabilidad de operaciones, detección de riesgos y auditoría técnica en sistemas de alto riesgo.",
        ]
        answer = "El Artículo 12 de la EU AI Act impone el registro automático de eventos (logging) y trazabilidad para auditoría técnica en sistemas de alto riesgo."
    elif "dora" in q_lower or "incidentes" in q_lower:
        contexts = [
            "DORA exige que las entidades financieras notifiquen incidentes TIC mayores a la autoridad competente: notificación inicial en 4 horas, informe intermedio en 72 horas e informe final en 1 mes.",
        ]
        answer = "Bajo DORA, los plazos de notificación de incidentes mayores a la autoridad competente son 4 horas inicial, 72 horas intermedio y 1 mes final."
    elif "ens" in q_lower or "inmutabilidad" in q_lower:
        contexts = [
            "El Esquema Nacional de Seguridad (ENS) en categoría Alta (medida op.mon.1) impone algoritmos acreditados por el CCN-CERT, sellado de tiempo e inmutabilidad de registros.",
        ]
        answer = "El ENS en categoría Alta (op.mon.1) exige cifrado acreditado por el CCN-CERT, sellado de tiempo e inmutabilidad de auditoría."
    else:
        contexts = [
            "La Directiva NIS2 (Art. 20) establece la responsabilidad personal de la alta dirección en ciberseguridad, con multas de hasta 10 millones de euros o 2% del volumen de negocio para entidades esenciales.",
        ]
        answer = "La Directiva NIS2 fija multas de 10 millones de euros o 2% anual y responsabilidad personal directa para la alta dirección en entidades esenciales."

    return answer, contexts


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    evaluator = RAGEvaluatorEngine()
    report = evaluator.run_benchmark_suite(mock_rag_predict, "rag_evaluation_report.json")
