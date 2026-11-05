import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
import os
#!/usr/bin/env python3
"""
iam_privilege_auditor.py - Auditor Estático de Accesos, Identidades y Privilegios TIC (DORA Art. 9).

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículo 9 (Control de Accesos e Identidades TIC).
- Exigencias:
    1. Principio de mínimo privilegio y separación de funciones (Segregation of Duties).
    2. Autenticación reforzada / Multi-Factor Authentication (MFA) para accesos privilegiados y remotos.
    3. Identificación y baja inmediata de cuentas huérfanas o inactivas (> 90 días).
    4. Revisión periódica de políticas de claves y secretos no rotados.

Descripción:
------------
Auditor de configuraciones IAM (Cloud/On-Prem/ActiveDirectory/JSON export) que evalúa cuentas huérfanas,
superusuarios sin MFA, permisos excesivos (wildcards "*") y políticas de acceso obsoletas.

Uso:
----
  python iam_privilege_auditor.py --generate-demo --output-dir ./iam_audit_reports
  python iam_privilege_auditor.py --input-config iam_export.json --output-dir ./iam_audit_reports
"""

import argparse
import datetime
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DORA_IAM_Auditor")


@dataclass
class IAMUserAccount:
    """Modelo de cuenta de usuario o identidad analizada."""

    username: str
    email: str
    role: str  # Admin, SuperAdmin, Developer, Auditor, ServiceAccount
    is_privileged_account: bool
    mfa_enabled: bool
    last_login_days_ago: int
    is_active: bool
    assigned_permissions: List[str]  # e.g. ["s3:*", "ec2:Describe*", "*:*"]
    password_age_days: int


@dataclass
class IAMFinding:
    """Hallazgo de auditoría de seguridad IAM."""

    finding_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    username: str
    issue_type: str  # ORPHANED_ACCOUNT, MISSING_MFA_ADMIN, EXCESSIVE_PRIVILEGES, OUTDATED_CREDENTIALS
    description: str
    dora_article_ref: str
    remediation_recommendation: str


@dataclass
class IAMAuditReport:
    """Informe completo de auditoría IAM conforme a DORA Art. 9."""

    entity_name: str
    audit_date: str
    total_accounts_scanned: int
    privileged_accounts_count: int
    orphaned_accounts_count: int
    admin_missing_mfa_count: int
    excessive_privilege_count: int
    findings_by_severity: Dict[str, int]
    findings: List[Dict[str, Any]]
    dora_compliance_score: float  # 0-100%
    dora_status: str  # CONFORME, NO_CONFORME_RIESGO_CRITICO


class DORAIAMPrivilegeAuditor:
    """Auditor estático de identidades e inmutabilidad de roles bajo DORA Art. 9."""

    def __init__(self, entity_name: str = "Entidad Financiera Audita"):
        self.entity_name = entity_name
        self.accounts: List[IAMUserAccount] = []

    def add_account(self, account: IAMUserAccount) -> None:
        self.accounts.append(account)

    def evaluate_audit(self) -> IAMAuditReport:
        """Audita todas las cuentas e identifica hallazgos de incumplimiento."""
        findings: List[IAMFinding] = []
        finding_counter = 1

        total_scanned = len(self.accounts)
        priv_count = 0
        orphaned_count = 0
        missing_mfa_count = 0
        excessive_priv_count = 0

        for acc in self.accounts:
            if acc.is_privileged_account or acc.role.lower() in ("admin", "superadmin", "root"):
                priv_count += 1

            # 1. Cuentas Huérfanas / Inactivas > 90 días (DORA Art. 9.1)
            if acc.is_active and acc.last_login_days_ago > 90:
                orphaned_count += 1
                findings.append(
                    IAMFinding(
                        finding_id=f"IAM-FIND-{finding_counter:03d}",
                        severity="HIGH",
                        username=acc.username,
                        issue_type="ORPHANED_ACCOUNT",
                        description=f"La cuenta activa '{acc.username}' no ha registrado sesión en {acc.last_login_days_ago} días (> 90 días).",
                        dora_article_ref="DORA Art. 9(1) / Control de Cuentas Inactivas",
                        remediation_recommendation="Desactivar o revocar la identidad inmediatamente y aplicar proceso de baja automatizado.",
                    )
                )
                finding_counter += 1

            # 2. Superusuarios / Administradores sin MFA (DORA Art. 9.4)
            if (acc.is_privileged_account or acc.role.lower() in ("admin", "superadmin", "root")) and not acc.mfa_enabled:
                missing_mfa_count += 1
                findings.append(
                    IAMFinding(
                        finding_id=f"IAM-FIND-{finding_counter:03d}",
                        severity="CRITICAL",
                        username=acc.username,
                        issue_type="MISSING_MFA_ADMIN",
                        description=f"La cuenta privilegiada '{acc.username}' ({acc.role}) NO tiene configurada la autenticación multifactor (MFA).",
                        dora_article_ref="DORA Art. 9(4) / Autenticación Reforzada de Accesos Privilegiados",
                        remediation_recommendation="Enforzar MFA por hardware (FIDO2/WebAuthn) o app OTP de manera obligatoria.",
                    )
                )
                finding_counter += 1

            # 3. Desviación del Mínimo Privilegio / Permisos Comodín "*" (DORA Art. 9.2)
            has_wildcard = any("*" in p for p in acc.assigned_permissions)
            if has_wildcard and not acc.role.lower() == "superadmin":
                excessive_priv_count += 1
                findings.append(
                    IAMFinding(
                        finding_id=f"IAM-FIND-{finding_counter:03d}",
                        severity="HIGH",
                        username=acc.username,
                        issue_type="EXCESSIVE_PRIVILEGES",
                        description=f"La cuenta '{acc.username}' posee políticas con comodines amplios: {acc.assigned_permissions}.",
                        dora_article_ref="DORA Art. 9(2) / Principio de Mínimo Privilegio",
                        remediation_recommendation="Restringir permisos a acciones específicas y recursos concretos (Least Privilege).",
                    )
                )
                finding_counter += 1

            # 4. Credenciales / Claves no rotadas > 180 días
            if acc.password_age_days > 180:
                findings.append(
                    IAMFinding(
                        finding_id=f"IAM-FIND-{finding_counter:03d}",
                        severity="MEDIUM",
                        username=acc.username,
                        issue_type="OUTDATED_CREDENTIALS",
                        description=f"La contraseña/clave API de '{acc.username}' no se ha rotado en {acc.password_age_days} días.",
                        dora_article_ref="DORA Art. 9(3) / Rotación de Contraseñas y Secretos",
                        remediation_recommendation="Forzar cambio de clave y definir política de caducidad automática.",
                    )
                )
                finding_counter += 1

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        # Cálculo de Score DORA (100 - penalizaciones por hallazgos)
        penalty = (sev_counts["CRITICAL"] * 25.0) + (sev_counts["HIGH"] * 10.0) + (sev_counts["MEDIUM"] * 3.0)
        score = max(0.0, round(100.0 - penalty, 2))

        status = "CONFORME_DORA_ART9" if score >= 85.0 and sev_counts["CRITICAL"] == 0 else "NO_CONFORME_RIESGO_CRITICO"

        return IAMAuditReport(
            entity_name=self.entity_name,
            audit_date=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            total_accounts_scanned=total_scanned,
            privileged_accounts_count=priv_count,
            orphaned_accounts_count=orphaned_count,
            admin_missing_mfa_count=missing_mfa_count,
            excessive_privilege_count=excessive_priv_count,
            findings_by_severity=sev_counts,
            findings=[asdict(f) for f in findings],
            dora_compliance_score=score,
            dora_status=status,
        )

    def export_json(self, report: IAMAuditReport, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Informe de Auditoría IAM JSON exportado en: {output_path}")

    def export_markdown(self, report: IAMAuditReport, output_path: Path) -> None:
        badge = "✅ CONFORME CON DORA ART. 9" if report.dora_status == "CONFORME_DORA_ART9" else "🚨 INCUMPLIMIENTO DORA - RIESGO DE ACCESOS CRÍTICO"
        
        md_content = f"""# Auditoría de Gestión de Identidades y Control de Accesos (DORA Art. 9)

**Entidad Financiera:** {report.entity_name}  
**Fecha de Auditoría:** {report.audit_date}  
**Puntuación de Cumplimiento DORA:** **{report.dora_compliance_score} / 100**  
**Dictamen de Accesos:** {badge}  

---

## 1. Resumen Ejecutivo del Control de Identidades

- **Cuentas Totales Escaneadas:** {report.total_accounts_scanned}
- **Cuentas Privilegiadas / Superusuarios:** {report.privileged_accounts_count}
- **Cuentas Huérfanas / Inactivas (>90 días):** {report.orphaned_accounts_count} ⚠️
- **Administradores Sín MFA:** {report.admin_missing_mfa_count} 🚨
- **Cuentas con Permisos Excesivos Comodín ("*"):** {report.excessive_privilege_count}

### Matriz de Hallazgos por Severidad
- 🔴 **CRÍTICO:** {report.findings_by_severity['CRITICAL']}
- 🟠 **ALTO:** {report.findings_by_severity['HIGH']}
- 🟡 **MEDIO:** {report.findings_by_severity['MEDIUM']}
- 🟢 **BAJO:** {report.findings_by_severity['LOW']}

---

## 2. Detalle de Vulnerabilidades e Incumplimientos IAM Detectados

| ID Hallazgo | Severidad | Usuario | Tipo de Incumplimiento | Referencia DORA | Recomendación de Remediación |
|-------------|-----------|---------|------------------------|-----------------|------------------------------|
"""
        for f in report.findings:
            sev_badge = f"🔴 {f['severity']}" if f['severity'] == 'CRITICAL' else f"🟠 {f['severity']}"
            md_content += f"| `{f['finding_id']}` | {sev_badge} | `{f['username']}` | {f['issue_type']} | {f['dora_article_ref']} | {f['remediation_recommendation']} |\n"

        md_content += f"""

---

## 3. Exigencias del Artículo 9 de DORA

> Las entidades financieras garantizarán la gestión segura de las identidades y los accesos TIC,
> aplicando el principio de mínimo privilegio, autenticación reforzada de doble factor (MFA) para
> funciones críticas y la revocación inmediata de privilegios obsoletos o no utilizados.

---
*Generado por `iam_privilege_auditor.py` el {report.audit_date}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Informe de Auditoría IAM Markdown exportado en: {output_path}")


def build_demo_accounts() -> DORAIAMPrivilegeAuditor:
    """Construye un conjunto de cuentas sintéticas para demostración y auditoría."""
    auditor = DORAIAMPrivilegeAuditor("Banco Digital de Resiliencia S.A.")

    a1 = IAMUserAccount(
        username="admin_sys",
        email="sysadmin@bancodigital.es",
        role="SuperAdmin",
        is_privileged_account=True,
        mfa_enabled=False,  # ALERTA CRÍTICA
        last_login_days_ago=2,
        is_active=True,
        assigned_permissions=["*:*"],
        password_age_days=45,
    )
    a2 = IAMUserAccount(
        username="dev_contractor_old",
        email="external_dev@vendor.com",
        role="Developer",
        is_privileged_account=False,
        mfa_enabled=True,
        last_login_days_ago=120,  # ALERTA HUÉRFANA (>90 días)
        is_active=True,
        assigned_permissions=["s3:GetObject"],
        password_age_days=130,
    )
    a3 = IAMUserAccount(
        username="operator_sec",
        email="secops@bancodigital.es",
        role="SecOps",
        is_privileged_account=True,
        mfa_enabled=True,
        last_login_days_ago=1,
        is_active=True,
        assigned_permissions=["ec2:*", "cloudwatch:*"],  # PERMISOS EXCESIVOS
        password_age_days=210,  # CLAVE CADUCADA
    )
    a4 = IAMUserAccount(
        username="auditor_compliance",
        email="auditor@bancodigital.es",
        role="Auditor",
        is_privileged_account=False,
        mfa_enabled=True,
        last_login_days_ago=5,
        is_active=True,
        assigned_permissions=["dora:ReadReports"],
        password_age_days=30,
    )

    auditor.add_account(a1)
    auditor.add_account(a2)
    auditor.add_account(a3)
    auditor.add_account(a4)

    return auditor


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auditor Estático de Accesos, Identidades y Privilegios TIC (DORA Art. 9)."
    )
    parser.add_argument("--generate-demo", action="store_true", help="Audita una muestra sintética de identidades IAM de prueba.")
    parser.add_argument("--input-config", type=Path, help="Fichero JSON con volcados de identidades y accesos IAM.")
    parser.add_argument("--output-dir", type=Path, default=Path("./iam_audit_output"), help="Directorio de salida de reportes.")

    args = parser.parse_args()

    if not args.generate_demo and not args.input_config:
        logger.info("No se especificaron entradas. Ejecutando auditoría sintética de prueba por defecto.")
        args.generate_demo = True

    try:
        if args.generate_demo:
            auditor = build_demo_accounts()
        else:
            with open(args.input_config, "r", encoding="utf-8") as f:
                data = json.load(f)
            auditor = DORAIAMPrivilegeAuditor(data.get("entity_name", "Entidad Financiera"))
            for acc in data.get("accounts", []):
                auditor.add_account(IAMUserAccount(**acc))

        report = auditor.evaluate_audit()

        out_json = args.output_dir / "dora_iam_audit_report.json"
        out_md = args.output_dir / "dora_iam_audit_report.md"

        auditor.export_json(report, out_json)
        auditor.export_markdown(report, out_md)

        logger.info(f"Auditoría IAM Finalizada. Score DORA: {report.dora_compliance_score}/100. Cuentas escaneadas: {report.total_accounts_scanned}.")
        
        if report.dora_status == "CONFORME_DORA_ART9":
            sys.exit(0)
        else:
            sys.exit(1)

    except Exception as e:
        logger.critical(f"Error durante la auditoría IAM DORA Art. 9: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
