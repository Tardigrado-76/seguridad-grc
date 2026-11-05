"""
Regulatory Role Archetypes and Separation of Duties for Quantigrade GCR.
Defines role boundaries, authorization matrices, and system prompts under
EU AI Act Art. 14, DORA Art. 6, and NIS2 Art. 20.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class RoleSpecification:
    role_name: str
    description: str
    primary_regulations: List[str]
    allowed_actions: Set[str]
    forbidden_actions: Set[str]
    system_prompt_template: str


@dataclass
class RoleActionDecision:
    role_name: str
    action: str
    is_authorized: bool
    reason: str


class RegulatoryRoleRegistry:
    """
    Formal role separation and boundary enforcement registry for autonomous GRC agents.
    """

    def __init__(self):
        self._roles: Dict[str, RoleSpecification] = {}
        self._register_default_archetypes()

    def _register_default_archetypes(self):
        self._roles["CISO"] = RoleSpecification(
            role_name="CISO",
            description="Chief Information Security Officer: Responsable de la ciberresiliencia y defensa perimetral.",
            primary_regulations=["DORA", "NIS2", "ENS", "ISO27001"],
            allowed_actions={
                "TRIGGER_ISOLATION_HARNESS",
                "COMMISSION_RED_TEAM_AUDIT",
                "APPROVE_TECHNICAL_REMEDIATION",
                "ASSESS_CYBER_RISKS",
            },
            forbidden_actions={
                "WAIVE_GDPR_RETENTION_POLICY",
                "BYPASS_AUDIT_TRAIL",
                "SUPPRESS_INCIDENT_REPORT",
            },
            system_prompt_template=(
                "Eres el Agente CISO de Quantigrade GCR. Tu mandato obligatorio bajo DORA (Art. 6) y NIS2 (Art. 21) "
                "es garantizar la seguridad tecnica, resiliencia perimetral y mitigacion de incidentes TIC. "
                "No tienes autoridad para omitir politicas de privacidad ni alterar cadenas de custodia."
            ),
        )

        self._roles["DPO"] = RoleSpecification(
            role_name="DPO",
            description="Data Protection Officer: Garante de la privacidad y proteccion de datos personales.",
            primary_regulations=["RGPD", "LOPDGDD", "EU_AI_ACT"],
            allowed_actions={
                "AUDIT_PII_FLOWS",
                "REJECT_NON_COMPLIANT_SAR",
                "APPROVE_PRIVACY_POLICY",
                "EVALUATE_DPIA",
            },
            forbidden_actions={
                "WAIVE_GDPR_RETENTION_POLICY",
                "DISABLE_PII_SANITIZER",
                "AUTHORIZE_UNPROTECTED_EXPORT",
            },
            system_prompt_template=(
                "Eres el Agente DPO de Quantigrade GCR. Tu mandato bajo el RGPD (Art. 38/39) y LOPDGDD "
                "es asegurar que todo tratamiento respete los derechos fundamentales de privacidad y soberania de datos. "
                "Es mandatorio bloquear cualquier flujo que contenga PII no anonimizada."
            ),
        )

        self._roles["INTERNAL_AUDITOR"] = RoleSpecification(
            role_name="INTERNAL_AUDITOR",
            description="Auditor Interno: Garante de la defensibilidad juridica, evidencia forense y cumplimiento penal.",
            primary_regulations=["ENS", "Art_31_bis_CP", "ISO27001", "eIDAS_2"],
            allowed_actions={
                "VERIFY_CHAIN_OF_CUSTODY",
                "GENERATE_LEGAL_DOSSIER",
                "REVISE_RISK_REGISTER",
                "AUDIT_MERKLE_BUNKER",
            },
            forbidden_actions={
                "EXECUTE_SYSTEM_PATCH",
                "MODIFY_EVIDENCE_LOG",
                "OVERRIDE_TIMESTAMP_PROOF",
            },
            system_prompt_template=(
                "Eres el Auditor Interno de Quantigrade GCR. Tu mandato bajo el Esquema Nacional de Seguridad (ENS) "
                "y el Codigo Penal espanol (Art. 31 bis CP) es validar la integridad probatoria y la cadena de custodia "
                "mediante sellado criptografico inmutable eIDAS 2.0."
            ),
        )

        self._roles["RED_TEAMER"] = RoleSpecification(
            role_name="RED_TEAMER",
            description="Especialista Ofensivo: Simulacion de adversarios, TLPT y descubrimiento de brechas.",
            primary_regulations=["DORA_TLPT", "OWASP_LLM_2025", "CRA"],
            allowed_actions={
                "RUN_PENTEST_SUITE",
                "DETECT_EXPLOITABLE_API",
                "SUBMIT_VULNERABILITY_REPORT",
                "SIMULATE_PROMPT_INJECTION",
            },
            forbidden_actions={
                "APPROVE_REMEDIATION_SIGN_OFF",
                "ALTER_PRODUCTION_CONFIG",
                "SUPPRESS_VULNERABILITY",
            },
            system_prompt_template=(
                "Eres el Agente Red Teamer de Quantigrade GCR. Tu mandato bajo DORA Art. 26 (TLPT) y OWASP LLM 2025 "
                "es someter a prueba de estres las defensas del sistema y descubrir vectores de ataque sin mitigar. "
                "Por separacion de funciones, no puedes aprobar ni certificar remediaciones."
            ),
        )

    def get_registered_roles(self) -> List[str]:
        """Returns the list of configured regulatory roles."""
        return sorted(list(self._roles.keys()))

    def get_system_prompt(self, role_name: str) -> str:
        """Generates the mandatory system prompt enforcing the role's legal mandate."""
        role = self._roles.get(role_name.upper())
        if not role:
            raise ValueError(f"Unknown regulatory role: {role_name}")
        return role.system_prompt_template

    def validate_action(self, role_name: str, action: str) -> RoleActionDecision:
        """
        Validates if an action is permitted under the role's separation-of-duties matrix.
        """
        role = self._roles.get(role_name.upper())
        if not role:
            return RoleActionDecision(
                role_name=role_name,
                action=action,
                is_authorized=False,
                reason=f"Role '{role_name}' is not recognized in the regulatory registry.",
            )

        act = action.strip().upper()

        if act in role.forbidden_actions:
            return RoleActionDecision(
                role_name=role_name,
                action=action,
                is_authorized=False,
                reason=f"Action '{action}' violates Separation of Duties policy for role '{role_name}'.",
            )

        if act in role.allowed_actions:
            return RoleActionDecision(
                role_name=role_name,
                action=action,
                is_authorized=True,
                reason=f"Action '{action}' is within authorized mandate of role '{role_name}'.",
            )

        # Fail-closed for undeclared actions
        return RoleActionDecision(
            role_name=role_name,
            action=action,
            is_authorized=False,
            reason=f"Action '{action}' is not explicitly permitted for role '{role_name}'.",
        )
