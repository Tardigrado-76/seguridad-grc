# Integración de Capacidades Scratch GRC en QUANTIGRADE GCR

## 1. Resumen Ejecutivo
Esta integración incorpora las capacidades clave de **scratch_grc** (Agentic RAG ReAct, Hybrid BM25/RRF, Self-RAG Hallucination Grading, y Mapeo Cruzado ISO 27001 / SOC 2) en **QUANTIGRADE GCR**.

Siguiendo la filosofía **Ponytail** (máxima densidad funcional, cero sobrecarga) y la directiva **Zero-Docker / Dual-Mode**:
- **Por defecto:** Motor 100% nativo en memoria y stdlib Python 3.13 (cero dependencias externas de contenedores ni bases de datos de red).
- **Modo Opcional Docker/Redis:** Si el entorno cuenta con Redis o el auditor especifica `REDIS_URL` o `--use-redis`, el sistema desacopla el almacenamiento de caché semántico y los checkpoints del StateGraph hacia Redis sin alterar el código de los agentes.

---

## 2. Módulos Implementados

| Módulo | Ruta | Propósito Operativo | Normativas / Estándares |
|:---|:---|:---|:---|
| **BM25 & Semantic Cache** | `core_mesh/operational/hybrid_rag_enhancements.py` | Búsqueda léxica exacta (BM25 Okapi), fusión RRF (k=60) y caché semántico (coseno $\ge 0.90$). | DORA Art. 6, ENS Alta |
| **Hallucination & CRAG Guard** | `core_mesh/operational/hallucination_faithfulness_guard.py` | Filtro de relevancia de evidencia (CRAG) y auditor de alucinaciones con ratio de fidelidad y linaje SHA-256. | EU AI Act Art. 9 & 13, OWASP LLM06 |
| **Agentic RAG Orchestrator** | `core_mesh/operational/agentic_rag_orchestrator.py` | Bucle ReAct multi-paso (Thought $\to$ Action $\to$ Observation $\to$ CRAG $\to$ Synthesis $\to$ Self-RAG). | EU AI Act, DORA, ENS, NIS2, RGPD |
| **ISO / SOC 2 Mapper** | `core_mesh/operational/iso_soc2_compliance_mapper.py` | Transposición automática de hallazgos técnicos hacia controles ISO 27001:2022 Anexo A y criterios SOC 2 TSC. | ISO/IEC 27001:2022, AICPA SOC 2 |

---

## 3. Guía de Ejecución

### 3.1 Consulta Agéntica ReAct (CLI)
```powershell
$env:PYTHONPATH="e:\PROYECTOS IA\PRODUCTION READY\100\github\QUANTIGRADE GCR"

# Modo Nativo (In-Memory stdlib)
python "core_mesh/operational/agentic_rag_orchestrator.py" -q "¿Cuáles son las obligaciones y sanciones bajo la Directiva NIS2?"

# Modo Dual con Redis (Opcional)
python "core_mesh/operational/agentic_rag_orchestrator.py" -q "Requisitos TLPT en DORA" --use-redis --redis-url "redis://localhost:6379/0"
```

### 3.2 Transposición a ISO 27001 y SOC 2
```powershell
# Exportación a formato Markdown
python "core_mesh/operational/iso_soc2_compliance_mapper.py" -f md

# Exportación a JSON auditado
python "core_mesh/operational/iso_soc2_compliance_mapper.py" -f json -o "informe_iso_soc2.json"
```

---

## 4. Cobertura de Pruebas Automatizadas
Suite dedicada: `core_mesh/tests/test_scratch_grc_integration.py`
- **18 pruebas unitarias e integración** pasadas al 100% (0.60s).
- **63 pruebas acumuladas** en la suite global de QUANTIGRADE GCR (ACE + Evidence Bunker SLSA L3+ + CTEM Validation Suite + PQC Hybrid Fuzzing + Scratch GRC).

