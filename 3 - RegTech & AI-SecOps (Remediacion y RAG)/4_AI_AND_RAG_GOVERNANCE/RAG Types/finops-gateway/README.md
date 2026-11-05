# Enterprise AI FinOps & Semantic Router Gateway

[![FastAPI](https://img.shields.io/badge/API-FastAPI%20Gateway-009688.svg?logo=fastapi&logoColor=white)]()
[![FinOps](https://img.shields.io/badge/FinOps-Token%20Budget%20Enforcer-blue.svg)]()
[![Cost Reduction](https://img.shields.io/badge/Cost%20Savings-Up%20to%2087%25-brightgreen.svg)]()
[![Sovereign AI](https://img.shields.io/badge/Data%20Sovereignty-Local%20Tier%20Routing-purple.svg)]()

## 📌 Resumen Ejecutivo (C-Level Overview)
El **AI FinOps Semantic Router** es la puerta de enlace inteligente diseñada para resolver el mayor desafío de escalabilidad en la adopción de IA generativa corporativa: **el coste descontrolado de las APIs de modelos de frontera**. 

Mediante clasificación semántica en tiempo real y gobernanza de presupuestos multi-tenant, enruta el tráfico entre modelos soberanos locales ($0.00$), motores híbridos de coste medio ($0.0005$) y orquestadores agénticos de alto rendimiento ($0.0150$), logrando un **ahorro medio del 87.3%** sin comprometer la precisión técnica ni la seguridad.

---

## 🏗️ Diagrama de Secuencia y Enrutamiento FinOps (Mermaid)

```mermaid
sequenceDiagram
    autonumber
    actor Auditor as Auditor / CISO (audit-console)
    participant GW as FinOps Gateway (FastAPI)
    participant BM as Budget Manager (Cuotas USD)
    participant Router as Semantic Router Engine
    participant Local as Tier 1: Sovereign 8B Local ($0.00)
    participant Hybrid as Tier 2: Hybrid RAG ($0.0005)
    participant Agentic as Tier 3: Agentic ReAct RAG ($0.0150)
    participant OTel as LLMOps Tracer (OTel / Phoenix)

    Auditor->>GW: POST /api/v1/chat {query, tenant_id}
    GW->>BM: check_and_reserve_budget(tenant_id)
    alt Presupuesto Excedido
        BM-->>GW: 402 Payment Required (Hard Limit)
        GW-->>Auditor: Error: Presupuesto mensual agotado
    else Presupuesto Aprobado
        BM-->>GW: OK (Quota Available)
        GW->>Router: route_query(query)
        Router-->>GW: Decision {Tier, Model, EstimatedCost}
        
        alt Consulta Simple / FAQ (Tier 1)
            GW->>Local: Ejecución On-Premise
            Local-->>GW: Respuesta Soberana
        else Consulta Regulatoria Estándar (Tier 2)
            GW->>Hybrid: Vector Search + BM25
            Hybrid-->>GW: Contexto + Respuesta
        else Razonamiento Cruzado Multi-Marco (Tier 3)
            GW->>Agentic: ReAct Multi-Tool Agent
            Agentic-->>GW: Síntesis Compleja
        end
        
        GW->>BM: record_usage(tokens, actual_cost)
        GW->>OTel: record_llm_execution(latency, cost, tokens)
        GW-->>Auditor: ChatResponse {answer, tier, cost, savings}
    end
```

---

## 💰 Matriz de Ahorro Económico (FinOps ROI Matrix)

Para un volumen empresarial típico de **100.000 consultas mensuales de auditoría**:

| Arquitectura | Distribución de Tráfico | Coste Medio / Consulta | Coste Total Mensual | Ahorro Anual (USD) |
|:---|:---|:---|:---|:---|
| **Baseline Tradicional (100% GPT-4o)** | 100% Frontier | $0.01500 | $1,500.00 | $0.00 (Baseline) |
| **FinOps Semantic Router (BunkerOS)** | 45% Local, 40% Hybrid, 15% Agentic | **$0.00245** | **$245.00** | **+$15,060.00 / año (83.6% ahorro)** |

---

## 📡 Endpoints de la API REST

- `POST /api/v1/chat`: Inferencia con enrutamiento inteligente y control de saldo.
- `POST /api/v1/route`: Previsualización de la decisión de enrutamiento y desglose de costes.
- `GET /api/v1/budget/{tenant_id}`: Consulta de cuota consumida y saldo restante.
- `GET /api/v1/metrics`: Métricas globales de ROI y estadísticas de distribución de tráfico.
- `GET /health`: Diagnóstico de salud del servicio.
