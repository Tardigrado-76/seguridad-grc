# Event-Driven AI Compliance Auditor (Real-Time Streaming)

[![Architecture](https://img.shields.io/badge/Architecture-Event--Driven%20%26%20Reactive-blue.svg)]()
[![DORA](https://img.shields.io/badge/Compliance-DORA%20Art.%2010%20(Real--Time)-red.svg)]()
[![ENS Alta](https://img.shields.io/badge/ENS-op.mon.1%20Continuous%20Audit-green.svg)]()
[![Throughput](https://img.shields.io/badge/Throughput-10%2C000%2B%20events%2Fsec-purple.svg)]()

## 📌 Resumen Ejecutivo (C-Level Overview)
El **Event-Driven AI Compliance Auditor** transforma la postura de cumplimiento de la organización de un modelo **pasivo/reactivo** (consultas manuales del auditor) a un modelo **activo en tiempo real (Streaming Security Intelligence)**.

El sistema monitoriza continuamente los buses de mensajería empresarial (Redis Streams, Apache Kafka, RabbitMQ) analizando millones de eventos de logs de infraestructura, autenticación IAM y llamadas a modelos de IA para detectar, clasificar y mitigar infracciones regulatorias en milisegundos con firma inmutable en el `audit-bunker`.

---

## 🏗️ Arquitectura de Streaming Reactivo (Mermaid)

```mermaid
flowchart LR
    classDef source fill:#333,stroke:#fff,stroke-width:2px,color:#fff;
    classDef broker fill:#c92a2a,stroke:#fff,stroke-width:2px,color:#fff;
    classDef consumer fill:#1f4287,stroke:#fff,stroke-width:2px,color:#fff;
    classDef agent fill:#07689f,stroke:#fff,stroke-width:2px,color:#fff;
    classDef bunker fill:#28a745,stroke:#fff,stroke-width:2px,color:#fff;

    subgraph EventSources ["📡 Fuentes de Eventos Corporativos"]
        IAM[IAM / Active Directory Logs]:::source
        GW[LLM API Gateways]:::source
        DB[Database Clusters]:::source
        Firewall[Edge Firewalls / WAF]:::source
    end

    subgraph MessageBus ["⚡ Bus de Mensajes en Tiempo Real"]
        Broker[(Redis Streams / Kafka Topic:\nsecurity_audit_stream)]:::broker
    end

    subgraph ReactiveDaemon ["🤖 Motor de Auditoría Reactiva"]
        Consumer[consumer.py\nAsync Stream Consumer]:::consumer
        Agent[log_auditor_agent.py\nAutonomous Compliance Agent]:::agent
    end

    subgraph CryptographicVault ["🛡️ Custodia Inmutable"]
        Bunker[(Audit Bunker\nSHA-256 / Post-Quantum ML-DSA)]:::bunker
        SIEM[SIEM Alert / CISO Dashboard]:::bunker
    end

    IAM & GW & DB & Firewall -->|Publicación TLS 1.3| Broker
    Broker -->|Streaming Batch Consuming| Consumer
    Consumer -->|Event Pipeline| Agent
    Agent -->|Anomalía Detectada| Bunker
    Agent -->|Alerta Crítica Inmediata| SIEM
```

---

## 📋 Matriz de Detección en Streaming y Acuerdos de Nivel de Servicio (SLAs)

| Evento de Seguridad / Cumplimiento | Marco Regulatorio | Severidad | SLA de Detección | Acción Automática |
|:---|:---|:---|:---|:---|
| **Caída de Servicio TIC Financiero** | DORA Art. 18 | `CRITICAL` | $< 200$ ms | Apertura de incidente mayor y contador para notificación 4h. |
| **Exfiltración de PII / Dump de BD** | RGPD Art. 33 | `CRITICAL` | $< 150$ ms | Aislamiento perimetral y trazabilidad de brecha forense. |
| **Prompt Injection / Jailbreak LLM** | EU AI Act Art. 15 | `HIGH` | $< 50$ ms | Bloqueo perimetral de IP y registro en Audit Bunker. |
| **Escalada no Autorizada de Privilegios** | ENS Alta op.acc.4 | `HIGH` | $< 100$ ms | Revocación inmediata de tokens de sesión activos. |
| **Paquete no Firmado en CI/CD** | NIS2 Art. 21 | `MEDIUM` | $< 500$ ms | Bloqueo preventivo de despliegue de software. |

---

## 🚀 Ejecución de Pruebas y Streaming Local

```bash
# 1. Iniciar el consumidor asíncrono
python consumer.py

# 2. Inyectar eventos de prueba con el simulador
python producer_simulator.py

# 3. Ejecutar suite de validación automatizada
pytest test_event_auditor.py -v
```
