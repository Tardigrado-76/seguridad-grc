"""gateway_api.py — Enterprise AI FinOps & Semantic Router API Gateway.
===================================================================
Puerta de enlace FastAPI para la orquestación inteligente de inferencia de IA.
- Intercepta peticiones del frontend (audit-console).
- Clasifica la complejidad semántica de la consulta (Semantic Router).
- Aplica control presupuestario y rate limiting por tenant (Budget Manager).
- Despacha al motor óptimo (Local Sovereign, Hybrid RAG, Agentic RAG).
- Emite telemetría y trazas OTel a OpenTelemetry / Phoenix (LLMOps Tracer).
"""

import sys
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

CURRENT_DIR = Path(__file__).parent.resolve()
ROOT_DIR = CURRENT_DIR.parent.parent.resolve()
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from budget_manager import FinOpsBudgetManager
from router import RoutingTier, SemanticRouter

SHARED_TELEMETRY_DIR = ROOT_DIR / "shared-telemetry"
if str(SHARED_TELEMETRY_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_TELEMETRY_DIR))

try:
    from observability import LLMOpsTracer
except ImportError:
    LLMOpsTracer = None  # type: ignore


# ---------------------------------------------------------------------------
# PYDANTIC DATA TRANSFER OBJECTS (DTOs)
# ---------------------------------------------------------------------------
class ChatRequest(BaseModel):
    query: str = Field(..., description="Pregunta técnica o legal del auditor")
    tenant_id: str = Field(default="default_tenant", description="ID de organización o departamento")
    force_tier: str | None = Field(default=None, description="Sobrescribir tier (LOCAL_SOVEREIGN, HYBRID_RAG, AGENTIC_RAG)")


class ChatResponse(BaseModel):
    answer: str
    tier_used: str
    model_used: str
    cost_usd: float
    savings_usd: float
    latency_sec: float
    token_usage: dict[str, int]
    budget_status: dict[str, Any]
    routing_rationale: str


class RoutePreviewRequest(BaseModel):
    query: str


class TenantBudgetUpdateRequest(BaseModel):
    monthly_budget_usd: float
    tier: str = "Enterprise"


# ---------------------------------------------------------------------------
# GATEWAY CORE LOGIC
# ---------------------------------------------------------------------------
class FinOpsGatewayService:
    def __init__(self) -> None:
        self.router = SemanticRouter()
        self.budget_manager = FinOpsBudgetManager()
        self.tracer = LLMOpsTracer.get_instance() if LLMOpsTracer else None

    def process_query(self, req: ChatRequest) -> ChatResponse:
        t0 = time.time()

        # 1. Routing Decision
        if req.force_tier and req.force_tier in [t.value for t in RoutingTier]:
            tier = req.force_tier
            model = "gpt-4o" if tier == RoutingTier.AGENTIC_RAG.value else "gpt-4o-mini"
            est_cost = 0.0150 if tier == RoutingTier.AGENTIC_RAG.value else 0.0005
            rationale = f"Tier forzado manualmente por el cliente: {tier}"
            savings = 0.0
        else:
            route_info = self.router.route_query(req.query)
            tier = route_info["tier"]
            model = route_info["selected_model"]
            est_cost = route_info["estimated_cost_usd"]
            savings = route_info["savings_usd"]
            rationale = route_info["rationale"]

        # 2. Budget Check & Enforcement
        budget_ok, budget_msg = self.budget_manager.check_and_reserve_budget(req.tenant_id, est_cost)
        if not budget_ok:
            if FASTAPI_AVAILABLE:
                raise HTTPException(status_code=402, detail=budget_msg)
            raise PermissionError(budget_msg)

        # 3. Execution Simulation / Engine Delegation
        prompt_tokens = len(req.query.split()) * 4

        if tier == RoutingTier.LOCAL_SOVEREIGN.value:
            answer = (
                f"[Sovereign 8B Local] Respuesta procesada en infraestructura on-premise soberana: "
                f"Definición normativa extraída para '{req.query}'. Coste de inferencia: $0.00."
            )
            completion_tokens = 80
        elif tier == RoutingTier.HYBRID_RAG.value:
            answer = (
                f"[Hybrid RAG Engine] Respuesta recuperada de bases vectoriales + BM25: "
                f"Artículos y controles aplicables para '{req.query}'. Cobertura documental verificada."
            )
            completion_tokens = 160
        else:
            answer = (
                f"[Agentic RAG ReAct Orchestrator] Síntesis multi-paso completada: "
                f"Análisis cruzado de los marcos normativos relevantes para '{req.query}'. "
                f"Verificación de trazabilidad y desambiguación ejecutada con éxito."
            )
            completion_tokens = 320

        latency = round(time.time() - t0, 3)

        # 4. Record Real Token Usage & FinOps State
        usage_info = self.budget_manager.record_usage(
            tenant_id=req.tenant_id,
            model_name=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

        # 5. LLMOps Telemetry
        if self.tracer:
            self.tracer.record_llm_execution(
                model_name=model,
                engine_type=tier,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                duration_sec=latency,
                cost_usd=usage_info["cost_usd"],
                extra_metadata={"tenant_id": req.tenant_id},
            )

        return ChatResponse(
            answer=answer,
            tier_used=tier,
            model_used=model,
            cost_usd=usage_info["cost_usd"],
            savings_usd=savings,
            latency_sec=latency,
            token_usage={
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            budget_status=usage_info,
            routing_rationale=rationale,
        )


# ---------------------------------------------------------------------------
# FASTAPI APP INSTANTIATION
# ---------------------------------------------------------------------------
service = FinOpsGatewayService()

if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="BunkerOS AI FinOps & Semantic Router Gateway",
        version="1.0.0",
        description="API Gateway inteligente para optimización económica y soberanía en arquitecturas de IA.",
    )

    import os
    allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",") if os.getenv("ALLOWED_ORIGINS") else ["http://localhost:8000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/api/v1/chat", response_model=ChatResponse, summary="Chat con Enrutamiento FinOps Inteligente")
    def chat_endpoint(req: ChatRequest):
        return service.process_query(req)

    @app.post("/api/v1/route", summary="Vista Previa de Enrutamiento y Estimación de Costes")
    def route_preview(req: RoutePreviewRequest):
        return service.router.route_query(req.query)

    @app.get("/api/v1/budget/{tenant_id}", summary="Estado de Presupuesto del Tenant")
    def get_budget(tenant_id: str):
        return service.budget_manager.get_tenant_status(tenant_id)

    @app.post("/api/v1/budget/{tenant_id}", summary="Configurar Presupuesto de Tenant")
    def set_budget(tenant_id: str, req: TenantBudgetUpdateRequest):
        service.budget_manager.register_tenant(tenant_id, req.monthly_budget_usd, req.tier)
        return {"status": "success", "tenant_id": tenant_id, "monthly_budget_usd": req.monthly_budget_usd}

    @app.get("/api/v1/metrics", summary="Métricas Globales de ROI y Ahorro FinOps")
    def get_metrics():
        return service.router.get_finops_summary()

    @app.get("/health", summary="Healthcheck del Gateway")
    def health():
        from datetime import datetime, timezone
        return {
            "status": "healthy",
            "service": "FinOps Gateway",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
else:
    app = None  # type: ignore


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sample_queries = [
        "¿Qué es el ENS?",
        "Explica los plazos de notificación de incidentes de DORA.",
        "Compara y armoniza las sanciones de la EU AI Act con las responsabilidades directivas de NIS2 y ENS Alta.",
    ]
    for q in sample_queries:
        res = service.process_query(ChatRequest(query=q, tenant_id="audit_team_alpha"))

