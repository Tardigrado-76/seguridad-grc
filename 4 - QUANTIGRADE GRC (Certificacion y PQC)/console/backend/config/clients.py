"""QUANTIGRADE GCR — ZERO-TRUST SCRIPTS & CLIENTS REGISTRY
Classified: Server-Side Operational Whitelist.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import TypedDict

BASE_QG_PATH = Path(__file__).resolve().parents[3]


class ClientConfig(TypedDict):
    name: str
    base_path: Path
    description: str
    allowed_modules: list[str]


class ScriptConfig(TypedDict):
    module: str
    relative_path: str
    interpreter: str  # "python" | "powershell" | "bash"
    requires_admin: bool
    description: str
    label: str
    risk_level: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    args: list[str]


CLIENTS_REGISTRY: dict[str, ClientConfig] = {
    "default_tenant": {
        "name": "Quantigrade Sovereign Enterprise Tenant",
        "base_path": BASE_QG_PATH,
        "description": "Entorno principal auditado por Quantigrade GCR.",
        "allowed_modules": ["audit", "hardening", "compliance", "chaos", "rag_backup"],
    },
    "dev_sandbox": {
        "name": "Quantigrade Dev/QA Sandbox",
        "base_path": BASE_QG_PATH,
        "description": "Entorno de staging para pruebas continuas sin privilegios administrativos.",
        "allowed_modules": ["audit", "compliance", "rag_backup"],
    },
}


SCRIPTS_REGISTRY: dict[str, ScriptConfig] = {
    # ── MÓDULO 1: Auditoría Técnica y Operacional ──
    "ast_scanner": {
        "module": "audit",
        "relative_path": "core_mesh/operational/ast_scanner.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Escáner AST de Dependencias y Excepciones",
        "description": "Análisis estático de código fuente, guardrails de excepciones y dependencias.",
        "risk_level": "LOW",
        "args": [],
    },
    "supply_chain_auditor": {
        "module": "audit",
        "relative_path": "core_mesh/operational/supply_chain_auditor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor Supply Chain & VEX Aggregator",
        "description": "Verificación de dependencias de terceros, KEV de CISA y SBOM VEX para NIS2.",
        "risk_level": "LOW",
        "args": [],
    },
    "iac_drift_auditor": {
        "module": "audit",
        "relative_path": "core_mesh/operational/iac_drift_auditor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor de Drift IaC Cloud (ENISA)",
        "description": "Escaneo de configuraciones Terraform y Kubernetes para detectar desviaciones de seguridad.",
        "risk_level": "LOW",
        "args": [],
    },
    "rng_entropy_monitor": {
        "module": "audit",
        "relative_path": "core_mesh/operational/rng_entropy_monitor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Monitor de Entropía FIPS 140-3 SP 800-90B",
        "description": "Supervisión continua de salud del generador de números aleatorios del sistema.",
        "risk_level": "LOW",
        "args": [],
    },
    "fips_zeroization": {
        "module": "audit",
        "relative_path": "core_mesh/operational/fips_zeroization_auditor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor de Zeroización de Claves FIPS 140-3",
        "description": "Verifica que el material criptográfico efímero sea destruido en memoria tras su uso.",
        "risk_level": "LOW",
        "args": [],
    },

    # ── MÓDULO 2: Remediación y Bastionado (Hardening) ──
    "ens_fim": {
        "module": "hardening",
        "relative_path": "core_mesh/remediation/ens_fim_enforcer.ps1",
        "interpreter": "powershell",
        "requires_admin": True,
        "label": "Integridad de Archivos ENS (FIM/HIDS)",
        "description": "Monitoriza y asegura la integridad de archivos y binarios críticos según el ENS.",
        "risk_level": "HIGH",
        "args": ["-ExecutionPolicy", "Bypass", "-NonInteractive"],
    },
    "disa_stig": {
        "module": "hardening",
        "relative_path": "core_mesh/remediation/disa_stig_hardening.ps1",
        "interpreter": "powershell",
        "requires_admin": True,
        "label": "Hardening DISA STIG / OTAN",
        "description": "Aplicación automatizada de directivas de seguridad DISA STIG para Windows Server.",
        "risk_level": "CRITICAL",
        "args": ["-ExecutionPolicy", "Bypass", "-NonInteractive"],
    },
    "harden_vps": {
        "module": "hardening",
        "relative_path": "core_mesh/remediation/harden_vps.sh",
        "interpreter": "bash",
        "requires_admin": True,
        "label": "Hardening Linux VPS",
        "description": "Bastionado de servidores Linux (sysctl, firewall, SSH y auditoría de accesos).",
        "risk_level": "HIGH",
        "args": [],
    },
    "kernel_harden": {
        "module": "hardening",
        "relative_path": "core_mesh/remediation/ip_kernel_hardening_auditor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor de Parámetros de Kernel",
        "description": "Inspecciona parámetros sysctl y flags del kernel del sistema operativo.",
        "risk_level": "LOW",
        "args": [],
    },
    "rgpd_purge": {
        "module": "hardening",
        "relative_path": "core_mesh/remediation/rgpd_data_retention_purger.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Purga y Destrucción Criptográfica RGPD Art. 17",
        "description": "Orquestador de derecho al olvido y purga de registros que exceden el periodo de retención.",
        "risk_level": "MEDIUM",
        "args": [],
    },

    # ── MÓDULO 3: Cumplimiento Normativo Activo (DORA, NIS2, RGPD) ──
    "dora_classifier": {
        "module": "compliance",
        "relative_path": "NORMATIVAS/DORA/dora_incident_classifier.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Clasificador de Incidentes Mayores DORA",
        "description": "Clasificación con umbrales oficiales EBA/RTS/2024/02 para incidentes TIC.",
        "risk_level": "LOW",
        "args": [],
    },
    "dora_failover": {
        "module": "compliance",
        "relative_path": "NORMATIVAS/DORA/dora_automated_failover_drill.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Simulador de Simulacros Failover DORA Art. 11/25",
        "description": "Verifica RTO y RPO durante simulacros automáticos de conmutación de servicios críticos.",
        "risk_level": "MEDIUM",
        "args": [],
    },
    "dora_third_party": {
        "module": "compliance",
        "relative_path": "NORMATIVAS/DORA/dora_ict_third_party_risk_auditor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor de Proveedores Terceros DORA Art. 28-30",
        "description": "Audita contratos de outsourcing TIC, concentraciones y cláusulas de salida.",
        "risk_level": "LOW",
        "args": [],
    },
    "dora_roi": {
        "module": "compliance",
        "relative_path": "NORMATIVAS/DORA/generate_dora_roi.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Registro de Información TIC DORA (RoI)",
        "description": "Genera los esquemas de reporting oficiales RT.01.01 a RT.08.01 para ESAs.",
        "risk_level": "LOW",
        "args": [],
    },
    "nis2_nca_reporter": {
        "module": "compliance",
        "relative_path": "NORMATIVAS/NIS2/nca_incident_reporter.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Notificador de Incidentes NIS2 / DORA a ANC",
        "description": "Generación de notificaciones de alerta temprana (24h), intermedia (72h) y final (1 mes).",
        "risk_level": "LOW",
        "args": [],
    },
    "rgpd_breach": {
        "module": "compliance",
        "relative_path": "NORMATIVAS/RGPD - LOPDGDD/rgpd_data_breach_auditor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor de Notificación de Brechas AEPD (72h)",
        "description": "Inspecciona el cumplimiento de plazos y contenido de comunicación ante brechas personales.",
        "risk_level": "LOW",
        "args": [],
    },

    # ── MÓDULO 4: Búnker de Evidencias SLSA L3+ & Resiliencia Criptográfica ──
    "slsa_provenance": {
        "module": "audit",
        "relative_path": "core_mesh/operational/slsa_provenance_engine.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Generador y Verificador de Proveniencia SLSA L3+",
        "description": "Atestación inmutable in-toto v1.0 con digests duales SHA-256/512 y enlace a SBOM.",
        "risk_level": "LOW",
        "args": [],
    },
    "zkp_auth": {
        "module": "audit",
        "relative_path": "core_mesh/operational/zkp_auth_gateway.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Pasarela de Autenticación Zero-Knowledge Proof (ZKP)",
        "description": "Autenticación Schnorr NIZK (Fiat-Shamir sobre secp256k1) sin exposición de credenciales.",
        "risk_level": "LOW",
        "args": [],
    },
    "log_immutability": {
        "module": "audit",
        "relative_path": "core_mesh/operational/immutable_log_verifier.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Verificador de Inmutabilidad de Logs DORA Art. 10",
        "description": "Auditoría de encadenamiento hash criptográfico y cálculo de raíz de árbol Merkle.",
        "risk_level": "LOW",
        "args": [],
    },
    "encrypted_vault": {
        "module": "hardening",
        "relative_path": "core_mesh/operational/encrypted_evidence_vault.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Bóveda de Evidencias Cifrada AES-256-GCM",
        "description": "Snapshot en caliente, derivación PBKDF2 y sanitización NIST SP 800-88.",
        "risk_level": "MEDIUM",
        "args": [],
    },
    "mtls_mesh": {
        "module": "hardening",
        "relative_path": "core_mesh/operational/mtls_mesh_factory.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Factoría de Certificados Mesh Mutual TLS (mTLS)",
        "description": "Generación y monitorización de certificados X.509 v3 con SAN y rotación continua.",
        "risk_level": "LOW",
        "args": [],
    },
    "cloud_exit_test": {
        "module": "compliance",
        "relative_path": "NORMATIVAS/DORA/cloud_exit_strategy_tester.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Validador de Estrategia de Salida Cloud DORA Art. 28.8",
        "description": "Simulacro de portabilidad de datos, sellado de backups y medición real de RTO y RPO.",
        "risk_level": "MEDIUM",
        "args": [],
    },
    "dora_chaos_test": {
        "module": "compliance",
        "relative_path": "NORMATIVAS/DORA/dora_chaos_resilience_tester.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Inyector de Caos y Resiliencia DORA Art. 25 (TLPT)",
        "description": "Inyección de fallos controlados (red, proceso, db) con mecanismo Panic Switch.",
        "risk_level": "HIGH",
        "args": [],
    },

    # ── MÓDULO 5: CTEM Validation Suite & Active Exposure Management ──
    "iam_privilege_ctem": {
        "module": "audit",
        "relative_path": "core_mesh/operational/iam_privilege_ctem.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor IAM CTEM (Mínimo Privilegio & MFA)",
        "description": "Detección de privilege creep, superusuarios sin MFA y cuentas huérfanas bajo DORA y ENS.",
        "risk_level": "LOW",
        "args": [],
    },
    "owasp_access_ctem": {
        "module": "audit",
        "relative_path": "core_mesh/operational/owasp_access_control_ctem.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor OWASP A01 Broken Access Control / IDOR",
        "description": "Inspección estática y dinámica de endpoints desprotegidos y riesgos BOLA/IDOR.",
        "risk_level": "LOW",
        "args": [],
    },
    "api_security_ctem": {
        "module": "audit",
        "relative_path": "core_mesh/operational/api_security_ctem_router.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Inspector de Seguridad API & Cabeceras HTTP",
        "description": "Auditoría de HSTS, CSP Level 3, Rate Limiting y CORS permisivo.",
        "risk_level": "LOW",
        "args": [],
    },
    "llm_rag_poisoning": {
        "module": "audit",
        "relative_path": "core_mesh/operational/llm_rag_poisoning_auditor.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor OWASP LLM03: Data Poisoning & Inyecciones RAG",
        "description": "Detección de puertas traseras, Unicode zero-width y código malicioso en corpus vectorial.",
        "risk_level": "LOW",
        "args": [],
    },
    "ens_vuln_patch_ctem": {
        "module": "audit",
        "relative_path": "core_mesh/operational/ens_vuln_patch_ctem.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor de Vulnerabilidades, EDR y Parches ENS",
        "description": "Verificación de antivirus/EDR activo, parches aplicados y firewall perimetral del host.",
        "risk_level": "LOW",
        "args": [],
    },
    "ens_access_ctem": {
        "module": "audit",
        "relative_path": "core_mesh/operational/ens_access_policy_ctem.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor de Políticas de Acceso ENS [op.acc.1]",
        "description": "Detección de permisos inseguros (777) y credenciales por defecto.",
        "risk_level": "LOW",
        "args": [],
    },
    "ai_compliance_ctem": {
        "module": "compliance",
        "relative_path": "core_mesh/operational/ai_compliance_ctem.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Motor de Cumplimiento EU AI Act (Reglamento UE 2024/1689)",
        "description": "Triaje de riesgo (Prohibido, Alto Riesgo, GPAI) y auditoría de supervisión humana Art. 14.",
        "risk_level": "LOW",
        "args": [],
    },
    "node_heartbeat": {
        "module": "hardening",
        "relative_path": "core_mesh/operational/node_heartbeat_telemetry.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Telemetría de Salud de Nodo con HMAC-SHA256",
        "description": "Balizas periódicas de integridad criptográfica y prevención de replay attacks.",
        "risk_level": "LOW",
        "args": [],
    },
    "otel_metrics": {
        "module": "hardening",
        "relative_path": "core_mesh/operational/otel_security_metrics.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Métricas de Seguridad OpenTelemetry & Fallback JSON",
        "description": "Exportación OTLP de eventos de seguridad y contadores locales de auditoría.",
        "risk_level": "LOW",
        "args": [],
    },
    "runtime_guard": {
        "module": "hardening",
        "relative_path": "core_mesh/operational/runtime_integrity_guard.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Supervisor de Integridad de Proceso y Memoria (Anti-Dump)",
        "description": "Detección en tiempo de ejecución de inyección de hilos, módulos de volcado y fuga de RAM.",
        "risk_level": "LOW",
        "args": [],
    },
    "ctem_orchestrator": {
        "module": "compliance",
        "relative_path": "core_mesh/operational/ctem_orchestrator.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Orquestador Maestro CTEM (Ciclo 5 Fases)",
        "description": "Ejecución del pipeline completo Discovery -> Scoping -> Prioritization -> Validation -> Mobilization.",
        "risk_level": "MEDIUM",
        "args": [],
    },

    # ── MÓDULO 6: Scratch GRC Sovereign AI & Cross-Framework Mapping ──
    "hybrid_rag_enhancements": {
        "module": "compliance",
        "relative_path": "core_mesh/operational/hybrid_rag_enhancements.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Motor Híbrido BM25 & Semantic LRU Cache",
        "description": "Búsqueda léxica Okapi BM25, fusión RRF y caché semántico (dual nativo / Redis).",
        "risk_level": "LOW",
        "args": [],
    },
    "hallucination_guard": {
        "module": "audit",
        "relative_path": "core_mesh/operational/hallucination_faithfulness_guard.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Auditor de Alucinaciones Self-RAG & CRAG Gate",
        "description": "Evaluación de fidelidad de respuestas, filtro de evidencia CRAG y linaje SHA-256.",
        "risk_level": "LOW",
        "args": [],
    },
    "agentic_rag": {
        "module": "compliance",
        "relative_path": "core_mesh/operational/agentic_rag_orchestrator.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Orquestador Multi-Agente Agentic RAG (ReAct)",
        "description": "Bucle autónomo ReAct con herramientas soberanas y persistencia dual memoria/Redis.",
        "risk_level": "LOW",
        "args": ["-q", "Consulta de cumplimiento normativo"],
    },
    "iso_soc2_mapper": {
        "module": "compliance",
        "relative_path": "core_mesh/operational/iso_soc2_compliance_mapper.py",
        "interpreter": "python",
        "requires_admin": False,
        "label": "Transpositor de Hallazgos a ISO 27001:2022 & SOC 2",
        "description": "Mapeo cruzado de hallazgos técnicos DORA/ENS/NIS2 a controles Anexo A y criterios TSC.",
        "risk_level": "LOW",
        "args": [],
    },
}


def resolve_script_path(client_id: str, script_id: str) -> Path:
    """Resuelve la ruta física del script según el registro Zero-Trust."""
    if client_id not in CLIENTS_REGISTRY:
        raise KeyError(f"Client ID '{client_id}' no reconocido en el registro.")
    if script_id not in SCRIPTS_REGISTRY:
        raise KeyError(f"Script ID '{script_id}' no reconocido en el registro.")

    client = CLIENTS_REGISTRY[client_id]
    script = SCRIPTS_REGISTRY[script_id]

    if script["module"] not in client["allowed_modules"]:
        raise PermissionError(
            f"Módulo '{script['module']}' no autorizado para el cliente '{client_id}'."
        )

    base = client["base_path"]
    full_path = (base / script["relative_path"]).resolve()

    # Evitar Directory Traversal
    try:
        full_path.relative_to(base)
    except ValueError as err:
        raise PermissionError("Path traversal detectado fuera del base_path.") from err

    if not full_path.exists():
        raise FileNotFoundError(f"Script físico no encontrado en disco: {full_path}")

    return full_path


def get_interpreter_cmd(interpreter: str) -> list[str]:
    """Retorna el comando de invocación del intérprete especificado."""
    if interpreter == "python":
        return [sys.executable]
    if interpreter == "powershell":
        ps = shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"
        return [ps, "-NoProfile", "-NonInteractive"]
    if interpreter == "bash":
        sh = shutil.which("bash") or shutil.which("sh") or "bash"
        return [sh]
    raise ValueError(f"Intérprete no soportado: '{interpreter}'.")

