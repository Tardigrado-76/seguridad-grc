"""router.py — Semantic Intent Router & Dynamic Model Dispatcher.
============================================================
Enrutador semántico de consultas para optimización FinOps y soberanía de datos.
Clasifica la complejidad de la consulta y la deriva al nivel óptimo:
- TIER 1 (Local / Free): Preguntas directas, definiciones, FAQs -> Local LLM / BM25
- TIER 2 (Hybrid RAG / Low Cost): Consultas estándar de un solo marco normativo -> Hybrid Vector Search
- TIER 3 (Agentic RAG / Frontier): Razonamiento cruzado multi-marco, síntesis compleja -> ReAct Agentic Engine

Calcula el ROI económico directo frente al baseline tradicional (100% Frontier LLMs).
"""

import logging
import re
from enum import Enum
from typing import Any

logger = logging.getLogger("FinOps.SemanticRouter")


class RoutingTier(str, Enum):
    LOCAL_SOVEREIGN = "LOCAL_SOVEREIGN"      # $0.00 Coste
    HYBRID_RAG = "HYBRID_RAG"                # ~$0.0005 Coste
    AGENTIC_RAG = "AGENTIC_RAG"              # ~$0.0150 Coste


class SemanticRouter:
    """Clasificador semántico y despachador de inferencia de bajo coste."""

    # Palabras clave que denotan complejidad alta y necesidad de razonamiento multi-agente
    COMPLEX_REASONING_TRIGGERS = [
        "compara", "comparar", "diferencias", "armoniza", "armonización",
        "impacto cruzado", "matriz de correlación", "auditoría completa",
        "plan de remediación", "conflicto entre", "evaluación global",
        "brecha de seguridad y sanción", "análisis de riesgos extremo",
    ]

    # Palabras clave de marcos normativos
    FRAMEWORK_KEYWORDS = {
        "eu_ai_act": ["eu ai act", "ia alto riesgo", "artículo 12", "artículo 14", "sistema prohibido", "conformidad ce"],
        "dora": ["dora", "resiliencia operativa", "incidentes tic", "concentración ict", "pruebas tlap"],
        "ens": ["ens", "esquema nacional", "ccn-cert", "categoría alta", "op.mon.1", "op.exp.8"],
        "nis2": ["nis2", "entidades esenciales", "responsabilidad directiva", "gestión de vulnerabilidades"],
        "rgpd": ["rgpd", "gdpr", "privacidad", "delegado de protección", "evaluación de impacto eipd"],
    }

    # Palabras clave que indican consultas simples de definición o ayuda
    SIMPLE_DEFINITION_TRIGGERS = [
        "qué es", "que es", "definición", "concepto", "significado", "resumen de",
        "acrónimo", "contacto", "ayuda", "version",
    ]

    # Palabras clave de procedimiento o requisitos regulatorios (Hybrid RAG)
    PROCEDURAL_TRIGGERS = [
        "plazos", "notificación", "requisitos", "procedimiento", "artículo",
        "obligaciones", "criterios", "medidas", "guía", "estándar", "explica",
    ]

    def __init__(self) -> None:
        self.total_routed_queries = 0
        self.tier_distribution = {
            RoutingTier.LOCAL_SOVEREIGN: 0,
            RoutingTier.HYBRID_RAG: 0,
            RoutingTier.AGENTIC_RAG: 0,
        }
        self.cumulative_savings_usd = 0.0

    def analyze_complexity(self, query: str) -> dict[str, Any]:
        """Analiza sintáctica y semánticamente la consulta para extraer métricas de complejidad."""
        q_lower = query.lower()
        word_count = len(re.findall(r"\b\w+\b", q_lower))

        # Detección de marcos normativos involucrados
        detected_frameworks = []
        for fw_name, keywords in self.FRAMEWORK_KEYWORDS.items():
            if any(kw in q_lower for kw in keywords):
                detected_frameworks.append(fw_name)

        # Detección de disparadores
        complex_triggers_found = [
            trigger for trigger in self.COMPLEX_REASONING_TRIGGERS if trigger in q_lower
        ]
        simple_triggers_found = [
            trigger for trigger in self.SIMPLE_DEFINITION_TRIGGERS if trigger in q_lower
        ]
        procedural_triggers_found = [
            trigger for trigger in self.PROCEDURAL_TRIGGERS if trigger in q_lower
        ]

        # Cálculo de Score de Complejidad [0.0 - 1.0]
        complexity_score = 0.4 if detected_frameworks else 0.1
        if word_count > 25:
            complexity_score += 0.2
        if len(detected_frameworks) > 1:
            complexity_score += 0.4  # Multi-framework requiere razonamiento cruzado
        if complex_triggers_found:
            complexity_score += 0.35
        if simple_triggers_found and not complex_triggers_found and not procedural_triggers_found:
            complexity_score = 0.15

        normalized_score = round(min(1.0, max(0.0, complexity_score)), 3)

        return {
            "query": query,
            "word_count": word_count,
            "detected_frameworks": detected_frameworks,
            "framework_count": len(detected_frameworks),
            "complex_triggers": complex_triggers_found,
            "simple_triggers": simple_triggers_found,
            "procedural_triggers": procedural_triggers_found,
            "complexity_score": normalized_score,
        }

    def route_query(self, query: str) -> dict[str, Any]:
        """Determina el nivel óptimo de inferencia y calcula el ahorro FinOps."""
        analysis = self.analyze_complexity(query)
        score = analysis["complexity_score"]
        fw_count = analysis["framework_count"]
        simple_triggers = analysis["simple_triggers"]
        complex_triggers = analysis["complex_triggers"]

        # Criterios de Enrutamiento
        if complex_triggers or fw_count >= 2 or score >= 0.70:
            tier = RoutingTier.AGENTIC_RAG
            selected_model = "gpt-4o"
            estimated_cost = 0.0150
            rationale = "Consulta multi-marco o análisis complejo: delegada a Agentic RAG con modelo de frontera."
        elif simple_triggers and not analysis["procedural_triggers"]:
            tier = RoutingTier.LOCAL_SOVEREIGN
            selected_model = "sovereign-compliance-8b"
            estimated_cost = 0.0
            rationale = "Consulta puntual o definición básica: resuelta con modelo soberano local sin coste de API."
        else:
            tier = RoutingTier.HYBRID_RAG
            selected_model = "gpt-4o-mini"
            estimated_cost = 0.0005
            rationale = "Consulta regulatoria estándar: resuelta vía Hybrid RAG (Vector + BM25 + Cross-Encoder)."

        # Actualizar métricas acumuladas
        self.total_routed_queries += 1
        self.tier_distribution[tier] += 1

        # Ahorro respecto al baseline (asumiendo que sin router todo va a GPT-4o a $0.0150)
        baseline_cost = 0.0150
        savings_this_query = max(0.0, baseline_cost - estimated_cost)
        self.cumulative_savings_usd = round(self.cumulative_savings_usd + savings_this_query, 6)

        return {
            "tier": tier.value,
            "selected_model": selected_model,
            "estimated_cost_usd": estimated_cost,
            "baseline_cost_usd": baseline_cost,
            "savings_usd": round(savings_this_query, 6),
            "rationale": rationale,
            "analysis": analysis,
        }

    def get_finops_summary(self) -> dict[str, Any]:
        """Devuelve el resumen global de ahorro y estadísticas de enrutamiento."""
        total = max(1, self.total_routed_queries)
        return {
            "total_queries_routed": self.total_routed_queries,
            "tier_distribution": {
                tier.value: {
                    "count": count,
                    "percentage": round((count / total) * 100, 2),
                }
                for tier, count in self.tier_distribution.items()
            },
            "cumulative_savings_usd": round(self.cumulative_savings_usd, 4),
            "roi_savings_percentage": round(
                (self.cumulative_savings_usd / (self.total_routed_queries * 0.0150)) * 100
                if self.total_routed_queries > 0 else 0.0, 2,
            ),
        }
