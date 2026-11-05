# Metodología CTEM (Continuous Threat Exposure Management) en Quantigrade GCR

## 1. Visión y Marco de Trabajo

Quantigrade GCR adopta el marco **Continuous Threat Exposure Management (CTEM)** promovido por Gartner, diseñado para transformar la ciberseguridad corporativa desde auditorías puntuales e inconexas hacia un ciclo de evaluación, validación activa y movilización continua de defensas.

El pipeline CTEM de Quantigrade opera a través de **5 Fases Deterministas** coordinadas por el `CTEMOrchestrator`:

```
┌─────────────────┐     ┌──────────────┐     ┌──────────────────┐     ┌────────────────┐     ┌──────────────────┐
│  1. DISCOVERY   │ ──> │  2. SCOPING  │ ──> │ 3. PRIORITIZE    │ ──> │ 4. VALIDATION  │ ──> │ 5. MOBILIZATION  │
│  Superficie TIC │     │  Límites GRC │     │ Exposure Index   │     │ Pentest Activo │     │ Remediación HITL │
└─────────────────┐     └──────────────┘     └──────────────────┘     └────────────────┘     └──────────────────┘
```

---

## 2. Descripción Operativa de las 5 Fases

### Fase 1: Discovery (Descubrimiento y Postura Base)
- **Objetivo**: Identificar activos, permisos, cuentas e higiene base del entorno.
- **Componentes**:
  - `iam_privilege_ctem.py`: Auditoría estática de accesos privilegiados, detección de cuentas huérfanas (>90 días) y superusuarios sin MFA bajo DORA Art. 9 y ENS `op.acc.1`.
  - `ens_vuln_patch_ctem.py`: Inspección de EDR/antimalware activo, gestión de parches/hotfixes y perfiles de firewall del host.
  - `ens_access_policy_ctem.py`: Escaneo estático de credenciales hardcodeadas y permisos excesivos (chmod 777).

### Fase 2: Scoping (Delimitación del Alcance y Criticidad)
- **Objetivo**: Mapear los activos descubiertos contra marcos normativos aplicables (ENS Categoría Alta, NIS2 Entidades Esenciales, DORA Entidades Financieras, EU AI Act Sistemas de Alto Riesgo).
- **Criterio**: Asignación de pesos y umbrales de severidad adaptados al perfil del inquilino (*tenant*).

### Fase 3: Prioritization (Priorización y Cálculo de Exposición)
- **Objetivo**: Evitar la fatiga de alertas traduciendo las vulnerabilidades técnicas en un **Índice de Exposición CTEM Normalizado (0.0 - 100.0)**.
- **Componente**: `ctem_exposure_scorer.py`:
  - Algoritmo de ponderación:
    - Hallazgo CRITICAL: +35.0 puntos
    - Hallazgo HIGH: +15.0 puntos
    - Hallazgo MEDIUM: +6.0 puntos
  - Salida discriminada por normativa: ENS, NIS2, DORA, EU AI Act, OWASP, RGPD.
  - Clasificación en niveles: *Low Exposure*, *Moderate*, *Elevated*, *Critical Exposure*.

### Fase 4: Validation (Validación Activa y Pruebas Ofensivas)
- **Objetivo**: Comprobar activamente si la exposición detectada puede ser explotada por un atacante antes de alertar al CISO.
- **Componentes**:
  - `owasp_access_control_ctem.py`: Verificación de riesgos IDOR, BOLA y endpoints administrativos sin decoradores de autenticación.
  - `api_security_ctem_router.py`: Validación de cabeceras HTTP defensivas (HSTS, CSP Level 3), rate limiting y CORS wildcard.
  - `llm_rag_poisoning_auditor.py`: Inspección de corpus RAG para detectar puertas traseras, Unicode invisible (zero-width) e inyecciones de prompt (OWASP LLM03).
  - `ai_compliance_ctem.py`: Clasificación de riesgo bajo el Reglamento UE 2024/1689 (EU AI Act) y verificación de supervisión humana (Art. 14).
  - `runtime_integrity_guard.py`: Detección en tiempo de ejecución de inyección de hilos, módulos de volcado (anti-dump) y agotamiento de RAM.

### Fase 5: Mobilization (Movilización y Remediación HITL)
- **Objetivo**: Desencadenar la respuesta técnica minimizando el tiempo de exposición (MTTR) con gobernanza humana obligatoria.
- **Mecanismos**:
  - Encolado de acciones prioritarias en `AutoRemediator`.
  - Acciones de aislamiento seguro (`auto_air_gap.ps1` / `auto_air_gap.sh`).
  - Sellado de informe final con Hash SHA-256 inmutable y proveniencia SLSA L3+.

---

## 3. Telemetría y Métricas en Tiempo Real

- **Balizas de Nodo (`node_heartbeat_telemetry.py`)**: Envío continuo de pulsos de salud firmados con HMAC-SHA256 y nonce aleatorio anti-repetición.
- **OpenTelemetry & Fallback (`otel_security_metrics.py`)**: Exportación dual mediante OTLP gRPC hacia recolectores centralizados (Prometheus, Grafana, Jaeger) con degradación grácil a logs JSON estructurados.

