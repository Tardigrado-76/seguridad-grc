"""
Git Security Live Mesh Connector
Cumplimiento CRA (Cyber Resilience Act Art. 10/11), DORA y ENS.
Auditoría continua de repositorios de código: detección de fugas de secretos,
políticas de bloqueo de ramas, presencia de lockfiles criptográficos y automatización de parches.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional


@dataclass
class GitAuditReport:
    repo_path: str
    has_gitignore: bool
    has_dependency_lockfile: bool
    has_automated_security_updates: bool
    secrets_found: int
    security_score: float
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class GitSecurityMesh:
    """Conector Live Mesh para la auditoría de seguridad y gobernanza en repositorios de código."""

    LOCKFILE_NAMES = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "Pipfile.lock", "Cargo.lock",
        "go.sum", "composer.lock", "requirements.txt"
    }

    DEPENDABOT_PATHS = [
        Path(".github/dependabot.yml"),
        Path(".github/dependabot.yaml"),
        Path(".gitlab-ci.yml"),
        Path("renovate.json"),
        Path(".snyk")
    ]

    SECRET_PATTERNS = [
        ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
        ("AWS_SECRET_KEY", re.compile(r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"][A-Za-z0-9/+=]{30,}['\"]")),
        ("OPENAI_SECRET_KEY", re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}")),
        ("GENERIC_API_KEY", re.compile(r"(?:api_key|apikey|secret_key)\s*=\s*['\"][A-Za-z0-9_-]{24,}['\"]", re.IGNORECASE)),
        ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"))
    ]

    EXCLUDE_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".idea", ".vscode"}

    def audit_repository(self, repo_path: Path | str) -> GitAuditReport:
        path = Path(repo_path).resolve()
        if not path.exists():
            return GitAuditReport(
                repo_path=str(path),
                has_gitignore=False,
                has_dependency_lockfile=False,
                has_automated_security_updates=False,
                secrets_found=0,
                security_score=0.0,
                findings=["Directorio de repositorio no encontrado."],
                recommendations=["Proporcionar una ruta válida a un repositorio de código."]
            )

        findings: List[str] = []
        recommendations: List[str] = []

        # 1. Verificar .gitignore
        has_gitignore = (path / ".gitignore").exists()
        if not has_gitignore:
            findings.append("Ausencia de .gitignore: riesgo crítico de fuga accidental de credenciales locales.")
            recommendations.append("Crear archivo .gitignore excluyendo .env, claves *.pem y artefactos de compilación.")

        # 2. Verificar lockfiles criptográficos (CRA Art. 10 SBOM y consistencia de dependencias)
        has_lockfile = False
        for lock_name in self.LOCKFILE_NAMES:
            if (path / lock_name).exists():
                has_lockfile = True
                break
        
        if not has_lockfile:
            findings.append("No se detectó lockfile de dependencias (poetry.lock, package-lock.json, etc.).")
            recommendations.append("Fijar árbol de dependencias con hashes criptográficos para garantizar trazabilidad CRA.")

        # 3. Verificar automatización de actualizaciones de seguridad
        has_sec_updates = any((path / rel_path).exists() for rel_path in self.DEPENDABOT_PATHS)
        if not has_sec_updates:
            findings.append("Falta de configuración para actualizaciones automáticas de vulnerabilidades (Dependabot/Renovate).")
            recommendations.append("Configurar .github/dependabot.yml para escaneo automatizado continuo de parches.")

        # 4. Escaneo estático de secretos
        secrets_count = 0
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            for file_name in files:
                file_path = Path(root) / file_name
                # Evitar archivos binarios grandes
                if file_path.stat().st_size > 1024 * 1024:
                    continue
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for pattern_name, pattern_re in self.SECRET_PATTERNS:
                        matches = pattern_re.findall(content)
                        if matches:
                            secrets_count += len(matches)
                            findings.append(f"Posible credencial expuesta ({pattern_name}) en {file_path.name}")
                except Exception:
                    continue

        if secrets_count > 0:
            recommendations.append(f"Revocar inmediatamente las {secrets_count} credenciales detectadas e incorporar un pre-commit hook.")

        # 5. Cálculo del score de seguridad Git (0 - 100)
        score = 0.0
        if has_gitignore:
            score += 25.0
        if has_lockfile:
            score += 25.0
        if has_sec_updates:
            score += 25.0
        
        # 25 puntos base para secretos; -15 puntos por cada secreto detectado
        secrets_subscore = max(0.0, 25.0 - (secrets_count * 15.0))
        score += secrets_subscore

        return GitAuditReport(
            repo_path=str(path),
            has_gitignore=has_gitignore,
            has_dependency_lockfile=has_lockfile,
            has_automated_security_updates=has_sec_updates,
            secrets_found=secrets_count,
            security_score=round(score, 1),
            findings=findings,
            recommendations=recommendations
        )
