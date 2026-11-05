"""Registro centralizado de rutas a scripts externos y reportes."""
import sys
from pathlib import Path

BASE_DIR = Path(r"E:\PROYECTOS IA")
AUDITORIAS = BASE_DIR / "AUDITORIAS"

NUEVO_ORDEN = AUDITORIAS / "NUEVO ORDEN"

PORTAL_CLIENTE = NUEVO_ORDEN / "1_PORTAL_CLIENTE"
CORE_ENGINES = NUEVO_ORDEN / "2_CORE_AUDIT_ENGINES"
BUNKER_DEFENSE = NUEVO_ORDEN / "3_BUNKER_AND_DEFENSE"
AI_RAG = NUEVO_ORDEN / "4_AI_AND_RAG_GOVERNANCE"
OPERATIONS = NUEVO_ORDEN / "5_OPERATIONS_AND_DOCS"
NEO_PORTFOLIO = AUDITORIAS / "NEO_PORTFOLIO"
NEW_AUDITS = BASE_DIR / "NEW AUDITS"

COMPLIANCE_PLATFORM = PORTAL_CLIENTE / "COMPILANCE_PLATFORM"
PRODUCTION_READY = AUDITORIAS / "PRODUCTION-READY"

SECURITY_AUDIT_DIR = BUNKER_DEFENSE / "security-audit"
BACKUP_INTEGRITY_DIR = BUNKER_DEFENSE / "backup-integrity"
DOC_GENERATORS_DIR = OPERATIONS / "doc-generators"
COMPLIANCE_FRAMEWORKS = CORE_ENGINES / "compliance-frameworks"
CLARA_FIX_TOOLS = CORE_ENGINES / "CLARA FIX TOOLS"
EU_AI_ACT_DIR = CORE_ENGINES / "compliance-frameworks" / "EU AI Act"

REPORTS_DIR = COMPLIANCE_PLATFORM / "REPORTS"
REPORTS_DORA = REPORTS_DIR / "DORA"
REPORTS_ENS = REPORTS_DIR / "ENS"
REPORTS_NIS2 = REPORTS_DIR / "NIS2"
REPORTS_RGPD = REPORTS_DIR / "RGPD"
REPORTS_CRA = REPORTS_DIR / "CRA"
REPORTS_EU_AI_ACT = REPORTS_DIR / "EU_AI_ACT"
REPORTS_OWASP = REPORTS_DIR / "OWASP"

COMPLIANCE_MANAGER = PORTAL_CLIENTE / "COMPLIANCE_MANAGER"
ORCHESTRATOR_CLI = COMPLIANCE_MANAGER / "orchestrator_cli.py"
EVALUATORS = COMPLIANCE_MANAGER / "src" / "evaluators"
REPORTERS = COMPLIANCE_MANAGER / "src" / "reporters"

DORA_SCRIPTS = CORE_ENGINES / "compliance-frameworks" / "DORA"
DORA_PDF_GEN = DORA_SCRIPTS / "dora_pdf_generator.py"

RGPD_DIR = NEO_PORTFOLIO / "audit-compliance-engine" / "src" / "compliance" / "rgpd"
NIS2_DIR = NEO_PORTFOLIO / "audit-compliance-engine" / "src" / "compliance" / "nis2"
CRYPTO_DIR = NEO_PORTFOLIO / "audit-compliance-engine" / "src" / "cryptography"
SAST_DAST_DIR = NEO_PORTFOLIO / "audit-compliance-engine" / "src" / "sast_dast"
SUPPLY_CHAIN_DIR = NEO_PORTFOLIO / "audit-compliance-engine" / "src" / "supply_chain"
HARDENING_DIR = NEO_PORTFOLIO / "audit-compliance-engine" / "src" / "hardening"
PQC_DIR = NEO_PORTFOLIO / "evidence-bunker-slsa3" / "src" / "pqc"
AI_GOVERNANCE_DIR = NEO_PORTFOLIO / "regulated-rag-ai-governance" / "src" / "governance"
AI_GUARDRAILS_DIR = NEO_PORTFOLIO / "regulated-rag-ai-governance" / "src" / "guardrails"
AI_SECURITY_DIR = NEO_PORTFOLIO / "regulated-rag-ai-governance" / "src" / "security"
AI_RESILIENCE_DIR = NEO_PORTFOLIO / "regulated-rag-ai-governance" / "src" / "resilience"
RESILIENCE_DIR = NEO_PORTFOLIO / "evidence-bunker-slsa3" / "src" / "resilience"
ZKP_DIR = NEO_PORTFOLIO / "evidence-bunker-slsa3" / "src" / "zkp"

SOAR_DIR = OPERATIONS / "workflow-automation"
# RAG Guardrails & Regulated AI
RAG_AUDIT_DIR = AI_RAG / "RAG Types" / "Guardrails_OWASP"
RAG_GUARDRAILS_DIR = COMPLIANCE_PLATFORM / "rag_guardrails"
RAG_REGULADO_APP = RAG_GUARDRAILS_DIR / "Rag_Regulado.py"
RAG_INGESTION_PIPELINE = RAG_GUARDRAILS_DIR / "rag_ingestion_pipeline.py"

HARDENING_SYSTEM = BUNKER_DEFENSE / "system-hardening"
CLARA_SUITE = HARDENING_SYSTEM / "ccn-cert-clara-suite"
DISA_STIGS = HARDENING_SYSTEM / "disa-stigs"

ENS_AUDITORS = NEW_AUDITS / "PRODUCTION-READY" / "AUDITOR"
NEW_AUDITS_PENTEST = NEW_AUDITS / "PRODUCTION-READY" / "AUDITOR" / "Pentesting_y_RedTeaming"

if str(DORA_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(DORA_SCRIPTS))
if str(COMPLIANCE_MANAGER) not in sys.path:
    sys.path.insert(0, str(COMPLIANCE_MANAGER))
