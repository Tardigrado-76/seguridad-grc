import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
"""
setup_git_hooks.py - Instalador y Gestor de Git Security Hooks (Cyber Resilience Act / ENS Alto).

Cumplimiento Regulatorio:
-------------------------
- Cyber Resilience Act (CRA): Exigencia de Seguridad por Diseño (Security-by-Design) en Repositorios.
- ENS (Nivel Alto): Art. 13 (Aseguramiento del Desarrollo y Prevención de Fugas de Secretos).
- NIS2 (Directiva UE 2022/2555): Art. 21(2)(d) (Gobernanza del Código y Prevención de Malware/Secretos).
- OWASP Top 10 2025: A03:2025 (Supply Chain Security & Secret Leaks).

Descripción:
------------
Instala y configura automáticamente los Git Pre-Commit Hooks de seguridad (Gitleaks, AST Scan, Linter)
en el repositorio local, impidiendo que claves de API, certificados o código no verificado sean subidos a Git.
Exporta informe de cumplimiento en JSON y Markdown.

Uso:
----
  python setup_git_hooks.py --repo-dir . --output-dir ./hooks_audit_reports
  python setup_git_hooks.py --install-gitleaks-config
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("Git_Security_Hooks_Installer")


@dataclass
class HookInstallStatus:
    """Estado de instalación de un hook individual."""

    hook_name: str
    target_path: str
    installed: bool
    executable: bool
    verification_passed: bool
    details: str


@dataclass
class GitHooksReport:
    """Reporte completo de la auditoría e instalación de Git Hooks."""

    audit_id: str
    timestamp: str
    repo_directory: str
    is_git_repository: bool
    pre_commit_installed: bool
    gitleaks_configured: bool
    integrity_hash: str
    hooks: List[Dict[str, Any]]
    dora_ens_verdict: str


class DORAGitHooksInstaller:
    """Instalador y verificador autónomo de Git Hooks de seguridad."""

    DEFAULT_PRE_COMMIT_CONFIG = """# Pre-Commit Configuration - Security & Compliance Gatekeeper (ENS Alto / CRA)
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.2
    hooks:
      - id: gitleaks
        name: Detect Secret Leaks (API Keys, Passwords, Certificates)
        entry: gitleaks detect --verbose --redact --staged
        language: golang
  - repo: local
    hooks:
      - id: ast-dependency-scan
        name: AST Dependency Scan
        entry: python DORA/ast_scan.py --path .
        language: system
        files: \\.py$
"""

    def __init__(self, repo_dir: Path):
        self.repo_dir = repo_dir.resolve()
        self.git_dir = self.repo_dir / ".git"

    def is_git_repo(self) -> bool:
        """Verifica si el directorio especificado es la raíz de un repositorio Git."""
        return self.git_dir.exists() and self.git_dir.is_dir()

    def install_gitleaks_config(self) -> Path:
        """Crea el archivo .pre-commit-config.yaml en la raíz si no existe."""
        config_path = self.repo_dir / ".pre-commit-config.yaml"
        if not config_path.exists():
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(self.DEFAULT_PRE_COMMIT_CONFIG.strip() + "\n")
            logger.info(f"Archivo de configuración '.pre-commit-config.yaml' creado en: {config_path}")
        return config_path

    def run_installation(self) -> GitHooksReport:
        """Instala y registra los hooks de Git pre-commit."""
        audit_id = f"HOOKS-AUDIT-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        if not self.is_git_repo():
            logger.error(f"El directorio '{self.repo_dir}' no es un repositorio Git válido.")
            return GitHooksReport(
                audit_id=audit_id,
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                repo_directory=str(self.repo_dir),
                is_git_repository=False,
                pre_commit_installed=False,
                gitleaks_configured=False,
                integrity_hash="",
                hooks=[],
                dora_ens_verdict="ERROR_DIRECTORIO_NO_GIT",
            )

        self.install_gitleaks_config()

        # Determinar ejecutable pre-commit o instalar vía pip si falta
        precommit_path = shutil.which("pre-commit")
        precommit_installed = precommit_path is not None

        if not precommit_installed:
            logger.info("Módulo 'pre-commit' no encontrado en el PATH. Instalando vía pip...")
            try:
                res = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "pre-commit"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if res.returncode == 0:
                    precommit_installed = True
                    logger.info("'pre-commit' instalado exitosamente en el entorno activo.")
            except Exception as ex:
                logger.error(f"No se pudo auto-instalar pre-commit: {ex}")

        hooks_status: List[HookInstallStatus] = []
        gitleaks_ok = False

        # Intentar ejecutar 'pre-commit install'
        hook_path = self.git_dir / "hooks" / "pre-commit"
        install_success = False
        details_msg = ""

        try:
            res = subprocess.run(
                ["pre-commit", "install"],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if res.returncode == 0:
                install_success = True
                gitleaks_ok = True
                details_msg = "Git pre-commit hook registrado correctamente."
                logger.info("Hook pre-commit de Git activado exitosamente.")
            else:
                details_msg = f"Error al ejecutar 'pre-commit install': {res.stderr.strip()}"
                logger.warning(details_msg)

        except Exception as ex:
            details_msg = f"Excepción durante la instalación del hook: {ex}"
            logger.error(details_msg)

        hooks_status.append(
            HookInstallStatus(
                hook_name="pre-commit (Gitleaks & AST Gatekeeper)",
                target_path=str(hook_path),
                installed=hook_path.exists(),
                executable=os.access(hook_path, os.X_OK) if hook_path.exists() else False,
                verification_passed=install_success,
                details=details_msg,
            )
        )

        verdict = "CONFORME_ENS_ALTO_CRA_SECURITY_HOOKS" if install_success else "HOOKS_SEGURIDAD_PENDIENTES"
        summary = f"{audit_id}|{install_success}|{gitleaks_ok}|{verdict}"
        integrity_hash = hashlib.sha256(summary.encode("utf-8")).hexdigest()

        return GitHooksReport(
            audit_id=audit_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            repo_directory=str(self.repo_dir),
            is_git_repository=True,
            pre_commit_installed=precommit_installed,
            gitleaks_configured=gitleaks_ok,
            integrity_hash=integrity_hash,
            hooks=[asdict(h) for h in hooks_status],
            dora_ens_verdict=verdict,
        )

    def export_json(self, report: GitHooksReport, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Informe de Git Hooks JSON exportado en: {output_path}")

    def export_markdown(self, report: GitHooksReport, output_path: Path) -> None:
        badge = "✅ GIT HOOKS DE SEGURIDAD ACTIVOS (CRA/ENS ALTO)" if report.dora_ens_verdict == "CONFORME_ENS_ALTO_CRA_SECURITY_HOOKS" else "⚠️ GIT HOOKS NO ACTIVADOS"

        md_content = f"""# Auditoría e Instalación de Git Security Hooks (CRA / ENS Alto)

**ID Auditoría:** `{report.audit_id}`  
**Repositorio Analizado:** `{report.repo_directory}`  
**Fecha de Instalación:** {report.timestamp}  
**Estado Compliance:** {badge}  
**Hash de Integridad:** `{report.integrity_hash[:16]}...`  

---

## 1. Resumen de Controles de Seguridad en Código

- **Repositorio Git Válido:** `{"SÍ" if report.is_git_repository else "NO"}`
- **Framework Pre-Commit Disponible:** `{"SÍ" if report.pre_commit_installed else "NO"}`
- **Regla Gitleaks (Detección de Secretos) Configurada:** `{"SÍ" if report.gitleaks_configured else "NO"}`

---

## 2. Detalle de Hooks Instalados en `.git/hooks/`

| Nombre del Hook | Ruta en Disco | Instalado | Ejecutable | Estado Verificación | Detalle |
|-----------------|---------------|-----------|------------|---------------------|---------|
"""
        for h in report.hooks:
            stat_icon = "✅ OK" if h['verification_passed'] else "❌ FALLO"
            md_content += f"| **{h['hook_name']}** | `{h['target_path']}` | {'SÍ' if h['installed'] else 'NO'} | {'SÍ' if h['executable'] else 'NO'} | {stat_icon} | {h['details']} |\n"

        md_content += f"""

---

## 3. Normativa y Hardening en el Entorno del Desarrollador

> **Cyber Resilience Act (CRA) & ENS Alto Art. 13:** Exigen que los desarrolladores dispongan de
> controles automáticos locales (*shift-left security*) que impidan subir credenciales, claves de API
> o certificados en claro al control de versiones.

---
*Generado por `setup_git_hooks.py` el {report.timestamp}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Informe de Git Hooks Markdown exportado en: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Instalador y Gestor de Git Security Hooks (Cyber Resilience Act / ENS Alto Art. 13)."
    )
    parser.add_argument("--repo-dir", type=Path, default=Path("."), help="Ruta a la raíz del repositorio Git (default: .).")
    parser.add_argument("--output-dir", type=Path, default=Path("./hooks_audit_reports"), help="Directorio de salida de informes.")

    args = parser.parse_args()

    try:
        installer = DORAGitHooksInstaller(args.repo_dir)
        report = installer.run_installation()

        out_json = args.output_dir / f"{report.audit_id}_hooks_report.json"
        out_md = args.output_dir / f"{report.audit_id}_hooks_report.md"

        installer.export_json(report, out_json)
        installer.export_markdown(report, out_md)

        if report.dora_ens_verdict == "CONFORME_ENS_ALTO_CRA_SECURITY_HOOKS":
            logger.info("Git Hooks de seguridad configurados e instalados con éxito.")
            sys.exit(0)
        else:
            logger.warning(f"Auditoría finalizada con advertencias: {report.dora_ens_verdict}.")
            sys.exit(1)

    except Exception as e:
        logger.critical(f"Error fatal durante la configuración de Git Hooks: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
