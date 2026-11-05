#!/usr/bin/env python3
"""
iam_privilege_ctem.py — CTEM Phase 1: IAM Privilege Discovery & Access Auditor.
Aligns with:
 - DORA (UE 2022/2554) Art. 9 (ICT Access Control & Identities)
 - ENS RD 311/2022: [op.acc.1] Control de Acceso
 - NIS2 (UE 2022/2555): Art. 21 Gestión de Accesos
 - OWASP Top 10 A01: Broken Access Control
"""
from __future__ import annotations

import datetime
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.IAM")


@dataclass
class IAMUserAccount:
    username: str
    email: str
    role: str
    is_privileged_account: bool
    mfa_enabled: bool
    last_login_days_ago: int
    is_active: bool
    assigned_permissions: list[str]
    password_age_days: int


@dataclass
class IAMFinding:
    finding_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    username: str
    issue_type: str
    description: str
    compliance_ref: str
    remediation_recommendation: str


class IAMPrivilegeCTEMAuditor:
    """Audits IAM accounts and access configurations for privilege creep and missing guards."""

    def __init__(self, entity_name: str = "Enterprise Target"):
        self.entity_name = entity_name

    def audit_accounts(self, accounts: list[IAMUserAccount]) -> dict[str, Any]:
        findings: list[IAMFinding] = []
        counter = 1

        for acc in accounts:
            # 1. Admin without MFA (CRITICAL)
            if acc.is_privileged_account and not acc.mfa_enabled:
                findings.append(IAMFinding(
                    finding_id=f"IAM-FIND-{counter:03d}",
                    severity="CRITICAL",
                    username=acc.username,
                    issue_type="ADMIN_MISSING_MFA",
                    description=f"Cuenta privilegiada '{acc.username}' ({acc.role}) sin MFA habilitado.",
                    compliance_ref="DORA Art. 9.4(c) / ENS [op.acc.1] / NIS2 Art. 21.2(i)",
                    remediation_recommendation="Imponer MFA de hardware (FIDO2/WebAuthn) obligatorio para todas las cuentas privilegiadas."
                ))
                counter += 1

            # 2. Orphaned or inactive account (HIGH)
            if acc.is_active and acc.last_login_days_ago > 90:
                findings.append(IAMFinding(
                    finding_id=f"IAM-FIND-{counter:03d}",
                    severity="HIGH",
                    username=acc.username,
                    issue_type="ORPHANED_ACCOUNT",
                    description=f"Cuenta inactiva durante {acc.last_login_days_ago} días sigue activa en el sistema.",
                    compliance_ref="DORA Art. 9.2 / ENS [op.acc.2]",
                    remediation_recommendation="Suspender inmediatamente cuentas con inactividad > 90 días y revocar llaves asociadas."
                ))
                counter += 1

            # 3. Wildcard or excessive permissions (HIGH)
            wildcards = [p for p in acc.assigned_permissions if "*:*" in p or p.endswith(":*") or p == "*"]
            if wildcards and acc.role.lower() not in ("breakglass", "superadmin"):
                findings.append(IAMFinding(
                    finding_id=f"IAM-FIND-{counter:03d}",
                    severity="HIGH",
                    username=acc.username,
                    issue_type="EXCESSIVE_PRIVILEGES",
                    description=f"Cuenta no superadmin posee permisos wildcard amplios: {wildcards}.",
                    compliance_ref="DORA Art. 9.1 (Least Privilege) / OWASP A01",
                    remediation_recommendation="Restringir permisos al principio de mínimo privilegio y separar funciones."
                ))
                counter += 1

            # 4. Outdated credentials / password age > 180 days (MEDIUM)
            if acc.password_age_days > 180:
                findings.append(IAMFinding(
                    finding_id=f"IAM-FIND-{counter:03d}",
                    severity="MEDIUM",
                    username=acc.username,
                    issue_type="OUTDATED_CREDENTIALS",
                    description=f"Clave de acceso sin rotar durante {acc.password_age_days} días.",
                    compliance_ref="ENS [op.acc.4] / DORA Art. 9.4",
                    remediation_recommendation="Forzar expiración y rotación periódica de credenciales estáticas."
                ))
                counter += 1

        total = len(accounts)
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")

        # Score calculation: base 100 minus weighted penalties
        penalty = (crit_count * 25) + (high_count * 10) + (med_count * 3)
        score = max(0.0, min(100.0, 100.0 - penalty))

        return {
            "entity": self.entity_name,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_accounts_scanned": total,
            "compliance_score": score,
            "status": "CONFORME" if crit_count == 0 and score >= 80.0 else "NO_CONFORME_RIESGO",
            "findings_count": len(findings),
            "findings_by_severity": {
                "CRITICAL": crit_count,
                "HIGH": high_count,
                "MEDIUM": med_count,
                "LOW": sum(1 for f in findings if f.severity == "LOW")
            },
            "findings": [asdict(f) for f in findings]
        }

    def audit_config_file(self, config_path: Path) -> dict[str, Any]:
        """Loads and audits IAM accounts from a JSON export."""
        p = Path(config_path)
        if not p.exists():
            return {
                "entity": self.entity_name,
                "error": f"Archivo de configuración no encontrado: {p}",
                "compliance_score": 0.0,
                "findings": []
            }
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            raw_accs = raw if isinstance(raw, list) else raw.get("accounts", [])
            accounts = [
                IAMUserAccount(
                    username=item.get("username", "unknown"),
                    email=item.get("email", ""),
                    role=item.get("role", "User"),
                    is_privileged_account=item.get("is_privileged_account", False),
                    mfa_enabled=item.get("mfa_enabled", False),
                    last_login_days_ago=item.get("last_login_days_ago", 0),
                    is_active=item.get("is_active", True),
                    assigned_permissions=item.get("assigned_permissions", []),
                    password_age_days=item.get("password_age_days", 0)
                )
                for item in raw_accs
            ]
            return self.audit_accounts(accounts)
        except Exception as e:
            logger.error("Error al auditar archivo IAM: %s", e)
            return {"entity": self.entity_name, "error": str(e), "compliance_score": 0.0, "findings": []}

