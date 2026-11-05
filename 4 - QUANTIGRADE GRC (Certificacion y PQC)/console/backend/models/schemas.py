"""QUANTIGRADE GCR — PYDANTIC SCHEMAS
Strict Zero-Trust validation for Console execution requests.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class ClientId(str, Enum):
    default_tenant = "default_tenant"
    dev_sandbox    = "dev_sandbox"


class ScriptId(str, Enum):
    # Audit
    ast_scanner          = "ast_scanner"
    supply_chain_auditor = "supply_chain_auditor"
    iac_drift_auditor    = "iac_drift_auditor"
    rng_entropy_monitor  = "rng_entropy_monitor"
    fips_zeroization     = "fips_zeroization"

    # Hardening
    ens_fim       = "ens_fim"
    disa_stig     = "disa_stig"
    harden_vps    = "harden_vps"
    kernel_harden = "kernel_harden"
    rgpd_purge    = "rgpd_purge"

    # Compliance
    dora_classifier   = "dora_classifier"
    dora_failover     = "dora_failover"
    dora_third_party  = "dora_third_party"
    dora_roi          = "dora_roi"
    nis2_nca_reporter = "nis2_nca_reporter"
    rgpd_breach       = "rgpd_breach"

    # Bunker SLSA L3+ & Cryptographic Resilience
    slsa_provenance   = "slsa_provenance"
    zkp_auth          = "zkp_auth"
    log_immutability  = "log_immutability"
    encrypted_vault   = "encrypted_vault"
    mtls_mesh         = "mtls_mesh"
    cloud_exit_test   = "cloud_exit_test"
    dora_chaos_test   = "dora_chaos_test"

    # CTEM Validation Suite & Active Exposure Management
    iam_privilege_ctem   = "iam_privilege_ctem"
    owasp_access_ctem    = "owasp_access_ctem"
    api_security_ctem    = "api_security_ctem"
    llm_rag_poisoning    = "llm_rag_poisoning"
    ens_vuln_patch_ctem  = "ens_vuln_patch_ctem"
    ens_access_ctem      = "ens_access_ctem"
    ai_compliance_ctem   = "ai_compliance_ctem"
    node_heartbeat       = "node_heartbeat"
    otel_metrics         = "otel_metrics"
    runtime_guard        = "runtime_guard"
    ctem_orchestrator    = "ctem_orchestrator"

    # Scratch GRC Sovereign AI & Cross-Framework Mapping
    hybrid_rag_enhancements = "hybrid_rag_enhancements"
    hallucination_guard     = "hallucination_guard"
    agentic_rag             = "agentic_rag"
    iso_soc2_mapper         = "iso_soc2_mapper"


class ModuleId(str, Enum):
    audit      = "audit"
    hardening  = "hardening"
    compliance = "compliance"
    chaos      = "chaos"
    rag_backup = "rag_backup"


class RiskLevel(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ExecuteRequest(BaseModel):
    client_id: ClientId = Field(..., description="ID lógico del cliente tenant")
    script_id: ScriptId = Field(..., description="ID del script a ejecutar")

    model_config = {"extra": "forbid"}


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    environment: str
    clients_registered: int
    scripts_registered: int


class ScriptInfo(BaseModel):
    script_id: str
    module: str
    label: str
    description: str
    interpreter: str
    requires_admin: bool
    risk_level: str


class ClientInfo(BaseModel):
    client_id: str
    name: str
    description: str
    allowed_modules: list[str]
    available_scripts: list[ScriptInfo]


class ErrorResponse(BaseModel):
    error: str
    detail: str

