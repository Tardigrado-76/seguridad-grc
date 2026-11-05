"""budget_manager.py — Enterprise AI FinOps & Token Budget Enforcer.
===============================================================
Control granular de cuotas, límites de gasto (Rate Limiting) y cálculo de costes en USD.
Cumplimiento: ISO/IEC 42001 (Control Presupuestario en IA), DORA (Gestión de Riesgo Financiero TIC)
"""

import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("FinOps.BudgetManager")


@dataclass
class ModelPricing:
    """Estructura de precios en USD por cada 1.000.000 de tokens."""

    input_price_per_m: float
    output_price_per_m: float


# Tabla de Precios Estándar de la Industria (Q3 2026)
PRICING_CATALOG: dict[str, ModelPricing] = {
    # Modelos Locales / Soberanos (Coste Inferencia Marginal = $0)
    "llama3-8b-local": ModelPricing(input_price_per_m=0.0, output_price_per_m=0.0),
    "mistral-7b-local": ModelPricing(input_price_per_m=0.0, output_price_per_m=0.0),
    "sovereign-compliance-8b": ModelPricing(input_price_per_m=0.0, output_price_per_m=0.0),

    # Modelos Mid-Tier (Hybrid RAG)
    "gpt-4o-mini": ModelPricing(input_price_per_m=0.15, output_price_per_m=0.60),
    "claude-3-5-haiku": ModelPricing(input_price_per_m=0.80, output_price_per_m=4.00),

    # Modelos Frontier (Agentic RAG / Multi-Step Reasoning)
    "gpt-4o": ModelPricing(input_price_per_m=2.50, output_price_per_m=10.00),
    "claude-3-5-sonnet": ModelPricing(input_price_per_m=3.00, output_price_per_m=15.00),
    "gemini-1-5-pro": ModelPricing(input_price_per_m=1.25, output_price_per_m=5.00),
}


@dataclass
class TenantBudget:
    tenant_id: str
    monthly_budget_usd: float
    used_usd: float = 0.0
    total_tokens_consumed: int = 0
    tier: str = "Enterprise"  # Standard, Premium, Enterprise
    hard_limit: bool = True
    last_reset_timestamp: float = field(default_factory=time.time)


class FinOpsBudgetManager:
    """Gestor de presupuestos FinOps y control de consumo para plataformas de IA."""

    def __init__(self, db_path: str = "finops_budget.db") -> None:
        self.db_path = db_path
        self._init_db()
        self.tenants: dict[str, TenantBudget] = self._load_from_db()
        
        # Sembrar un tenant por defecto para auditoría si no existen
        if "default_tenant" not in self.tenants:
            self.register_tenant("default_tenant", monthly_budget_usd=100.0, tier="Enterprise")
        if "audit_team_alpha" not in self.tenants:
            self.register_tenant("audit_team_alpha", monthly_budget_usd=250.0, tier="Premium")

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                monthly_budget_usd REAL,
                used_usd REAL,
                total_tokens_consumed INTEGER,
                tier TEXT,
                hard_limit INTEGER,
                last_reset_timestamp REAL
            )''')
            
    def _load_from_db(self) -> dict[str, TenantBudget]:
        tenants = {}
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT tenant_id, monthly_budget_usd, used_usd, total_tokens_consumed, tier, hard_limit, last_reset_timestamp FROM tenants")
            for row in cursor.fetchall():
                t = TenantBudget(
                    tenant_id=row[0],
                    monthly_budget_usd=row[1],
                    used_usd=row[2],
                    total_tokens_consumed=row[3],
                    tier=row[4],
                    hard_limit=bool(row[5]),
                    last_reset_timestamp=row[6]
                )
                tenants[row[0]] = t
        return tenants
        
    def _save_tenant(self, tenant: TenantBudget):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''INSERT OR REPLACE INTO tenants 
                (tenant_id, monthly_budget_usd, used_usd, total_tokens_consumed, tier, hard_limit, last_reset_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                (tenant.tenant_id, tenant.monthly_budget_usd, tenant.used_usd, tenant.total_tokens_consumed, tenant.tier, int(tenant.hard_limit), tenant.last_reset_timestamp))

    def register_tenant(self, tenant_id: str, monthly_budget_usd: float, tier: str = "Standard") -> TenantBudget:
        budget = TenantBudget(
            tenant_id=tenant_id,
            monthly_budget_usd=monthly_budget_usd,
            tier=tier,
        )
        self.tenants[tenant_id] = budget
        self._save_tenant(budget)
        return budget

    def calculate_cost(self, model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Calcula el coste exacto en USD para una llamada dada."""
        pricing = PRICING_CATALOG.get(model_name, PRICING_CATALOG["gpt-4o-mini"])
        input_cost = (prompt_tokens / 1_000_000) * pricing.input_price_per_m
        output_cost = (completion_tokens / 1_000_000) * pricing.output_price_per_m
        return round(input_cost + output_cost, 6)

    def check_and_reserve_budget(self, tenant_id: str, estimated_cost_usd: float = 0.005) -> tuple[bool, str]:
        """Verifica si el tenant tiene presupuesto suficiente para ejecutar la consulta."""
        if tenant_id not in self.tenants:
            self.register_tenant(tenant_id, monthly_budget_usd=50.0)

        tenant = self.tenants[tenant_id]

        if tenant.hard_limit and (tenant.used_usd + estimated_cost_usd > tenant.monthly_budget_usd):
            msg = (
                f"[BudgetExceeded] Tenant '{tenant_id}' ha consumido ${tenant.used_usd:.2f} "
                f"de su presupuesto mensual de ${tenant.monthly_budget_usd:.2f}."
            )
            logger.warning(msg)
            return False, msg

        return True, "Presupuesto disponible"

    def record_usage(
        self,
        tenant_id: str,
        model_name: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> dict[str, Any]:
        """Registra el consumo real y actualiza el saldo del tenant."""
        if tenant_id not in self.tenants:
            self.register_tenant(tenant_id, monthly_budget_usd=50.0)

        cost = self.calculate_cost(model_name, prompt_tokens, completion_tokens)
        tenant = self.tenants[tenant_id]

        tenant.used_usd = round(tenant.used_usd + cost, 6)
        tenant.total_tokens_consumed += (prompt_tokens + completion_tokens)
        self._save_tenant(tenant)

        percent_used = (tenant.used_usd / tenant.monthly_budget_usd) * 100 if tenant.monthly_budget_usd > 0 else 0.0

        return {
            "tenant_id": tenant_id,
            "cost_usd": cost,
            "used_usd": tenant.used_usd,
            "budget_usd": tenant.monthly_budget_usd,
            "budget_percent_used": round(percent_used, 2),
            "total_tokens": tenant.total_tokens_consumed,
        }

    def get_tenant_status(self, tenant_id: str) -> dict[str, Any]:
        """Devuelve el estado financiero y consumo del tenant."""
        if tenant_id not in self.tenants:
            return {"error": "Tenant not found"}

        t = self.tenants[tenant_id]
        return {
            "tenant_id": t.tenant_id,
            "tier": t.tier,
            "monthly_budget_usd": t.monthly_budget_usd,
            "used_usd": round(t.used_usd, 4),
            "remaining_budget_usd": round(max(0.0, t.monthly_budget_usd - t.used_usd), 4),
            "total_tokens_consumed": t.total_tokens_consumed,
            "utilization_rate_pct": round((t.used_usd / t.monthly_budget_usd) * 100, 2),
        }
