"""test_finops_gateway.py — Unit Tests for FinOps Semantic Router & Budget Manager.
==============================================================================
Pruebas de enrutamiento dinámico, cuotas de tokens y ahorro de costes.
"""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).parent.resolve()
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from budget_manager import FinOpsBudgetManager
from gateway_api import ChatRequest, FinOpsGatewayService
from router import RoutingTier, SemanticRouter


def test_semantic_router_simple_query() -> None:
    router = SemanticRouter()
    decision = router.route_query("¿Qué es el ENS?")
    assert decision["tier"] == RoutingTier.LOCAL_SOVEREIGN.value
    assert decision["estimated_cost_usd"] == 0.0
    assert decision["savings_usd"] == 0.0150


def test_semantic_router_hybrid_query() -> None:
    router = SemanticRouter()
    decision = router.route_query("Explica los plazos de notificación de incidentes según DORA.")
    assert decision["tier"] == RoutingTier.HYBRID_RAG.value
    assert decision["estimated_cost_usd"] == 0.0005


def test_semantic_router_complex_agentic_query() -> None:
    router = SemanticRouter()
    query = "Compara y armoniza los requisitos de trazabilidad de la EU AI Act con las obligaciones de NIS2 y auditoría de ENS Alta."
    decision = router.route_query(query)
    assert decision["tier"] == RoutingTier.AGENTIC_RAG.value
    assert decision["estimated_cost_usd"] == 0.0150


def test_budget_manager_cost_calculation() -> None:
    mgr = FinOpsBudgetManager()
    # 1000 prompt tokens + 500 completion tokens in gpt-4o ($2.50 input / $10.00 output per M)
    cost = mgr.calculate_cost("gpt-4o", 1000, 500)
    # (1000/1M * 2.50) + (500/1M * 10.00) = 0.0025 + 0.0050 = 0.0075
    assert cost == 0.0075


def test_budget_manager_hard_limit() -> None:
    mgr = FinOpsBudgetManager()
    mgr.register_tenant("budget_restricted", monthly_budget_usd=0.01)

    # First query consumes budget
    mgr.record_usage("budget_restricted", "gpt-4o", 2000, 1000)

    # Next reservation should be rejected
    ok, msg = mgr.check_and_reserve_budget("budget_restricted", 0.01)
    assert ok is False
    assert "BudgetExceeded" in msg


def test_gateway_service_execution() -> None:
    service = FinOpsGatewayService()
    req = ChatRequest(query="¿Qué es DORA?", tenant_id="test_unit_tenant")
    res = service.process_query(req)

    assert res.tier_used == RoutingTier.LOCAL_SOVEREIGN.value
    assert res.savings_usd > 0
    assert res.latency_sec >= 0.0
