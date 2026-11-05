import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
"""
ast_scan.py - Escáner Estático de Dependencias Python basado en AST (ENS Alto / NIS2 / DORA).

Cumplimiento Regulatorio:
-------------------------
- ENS (Nivel Alto): Art. 12 (Seguridad en la Cadena de Suministro y Gestión de Componentes).
- NIS2 (Directiva UE 2022/2555): Art. 21(2)(d) (Seguridad de la Cadena de Suministro).
- DORA (Reglamento UE 2022/2554): Art. 28 (Gestión de Riesgos de Terceros TIC).
- OWASP Top 10 2025: A03:2025 (Software and Data Integrity Failures / Supply Chain Risks).

Descripción:
------------
Realiza un análisis sintáctico abstracto (AST) del código fuente Python para descubrir
todas las importaciones de terceros, verificar su instalación en el entorno local
y generar un reporte auditable de dependencias detectadas y faltantes en JSON y Markdown.

Uso:
----
  python ast_scan.py --path ./src --output-dir ./audit_reports
  python ast_scan.py --path . --format json
"""

import argparse
import ast
import datetime
import hashlib
import importlib.util
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AST_Dependency_Scanner")


# Mapeo de nombres de módulos importados a nombres de paquetes PyPI oficiales
MODULE_TO_PYPI_MAPPING: Dict[str, str] = {
    "dotenv": "python-dotenv",
    "argon2": "argon2-cffi",
    "jwt": "PyJWT",
    "pytest_asyncio": "pytest-asyncio",
    "httpcore": "httpcore2",
    "httpx2": "httpx2",
    "win32crypt": "pywin32",
    "yaml": "PyYAML",
    "OpenSSL": "pyOpenSSL",
    "opentelemetry": "opentelemetry-api",
    "pkcs11": "python-pkcs11",
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
}

IGNORED_DIRECTORIES: Set[str] = {
    ".venv",
    "venv",
    "env",
    ".git",
    "dist",
    "build",
    ".pytest_cache",
    ".flake8_cache",
    "node_modules",
    "__pycache__",
}


@dataclass
class DependencyItem:
    """Representa una dependencia detectada mediante AST."""

    module_name: str
    pypi_package_name: str
    is_installed: bool
    source_files: List[str] = field(default_factory=list)


@dataclass
class ASTScanReport:
    """Reporte completo del escaneo estático AST de dependencias."""

    scan_id: str
    scan_timestamp: str
    target_path: str
    total_files_scanned: int
    total_dependencies_found: int
    installed_dependencies_count: int
    missing_dependencies_count: int
    integrity_hash: str
    detected_dependencies: List[Dict[str, Any]]
    missing_dependencies: List[Dict[str, Any]]
    scan_errors: List[Dict[str, str]]
    compliance_status: str


class ASTDependencyScanner:
    """Escáner estático AST autónomo de dependencias de código Python."""

    def __init__(self, target_path: Path):
        self.target_path = self._sanitize_path(target_path)
        self.detected_modules: Dict[str, List[str]] = {}
        self.scan_errors: List[Dict[str, str]] = []

    def _sanitize_path(self, path: Path) -> Path:
        """Previene Path Traversal y asegura la existencia del directorio."""
        resolved = path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"La ruta especificada no existe: {resolved}")
        return resolved

    def _collect_python_files(self) -> List[Path]:
        """Colecciona de forma segura todos los archivos .py omitiendo directorios ignorados."""
        py_files: List[Path] = []
        if self.target_path.is_file() and self.target_path.suffix == ".py":
            return [self.target_path]

        for root, dirs, files in os.walk(self.target_path):
            # Filtrar in-place directorios no deseados
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]
            for file_name in files:
                if file_name.endswith(".py"):
                    py_files.append(Path(root) / file_name)
        return py_files

    def scan(self) -> ASTScanReport:
        """Realiza la extracción AST e inspección de módulos importados."""
        scan_id = f"AST-SCAN-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        py_files = self._collect_python_files()
        imported_modules: Dict[str, Set[str]] = {}

        for file_path in py_files:
            rel_file_str = str(file_path.relative_to(self.target_path) if self.target_path.is_dir() else file_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                
                tree = ast.parse(content, filename=str(file_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            root_mod = alias.name.split(".")[0]
                            if root_mod:
                                imported_modules.setdefault(root_mod, set()).add(rel_file_str)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            root_mod = node.module.split(".")[0]
                            if root_mod:
                                imported_modules.setdefault(root_mod, set()).add(rel_file_str)

            except SyntaxError as se:
                logger.warning(f"Error de sintaxis AST en {rel_file_str}: {se}")
                self.scan_errors.append({"file": rel_file_str, "error": f"SyntaxError: {se}"})
            except Exception as ex:
                logger.error(f"Error al procesar el archivo {rel_file_str}: {ex}")
                self.scan_errors.append({"file": rel_file_str, "error": f"Read/Parse Error: {ex}"})

        # Módulos estándar de Python
        stdlib_modules = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()

        # Módulos locales del proyecto
        local_modules: Set[str] = set()
        if self.target_path.is_dir():
            for child in self.target_path.iterdir():
                if child.is_dir() or child.suffix == ".py":
                    local_modules.add(child.stem)

        detected_list: List[DependencyItem] = []
        missing_list: List[DependencyItem] = []

        for mod_name in sorted(imported_modules.keys()):
            if mod_name in stdlib_modules or mod_name in local_modules or not mod_name:
                continue

            pypi_name = MODULE_TO_PYPI_MAPPING.get(mod_name, mod_name)
            source_files = sorted(list(imported_modules[mod_name]))

            # Verificar disponibilidad local
            try:
                spec = importlib.util.find_spec(mod_name)
                is_installed = spec is not None
            except Exception:
                is_installed = False

            item = DependencyItem(
                module_name=mod_name,
                pypi_package_name=pypi_name,
                is_installed=is_installed,
                source_files=source_files,
            )

            if is_installed:
                detected_list.append(item)
            else:
                missing_list.append(item)

        total_deps = len(detected_list) + len(missing_list)
        compliance_status = "CONFORME_CADENA_SUMINISTRO" if len(missing_list) == 0 else "ALERTA_DEPENDENCIAS_FALTANTES"

        # Hash de integridad del informe
        summary_payload = f"{scan_id}|{len(py_files)}|{total_deps}|{len(missing_list)}"
        integrity_hash = hashlib.sha256(summary_payload.encode("utf-8")).hexdigest()

        return ASTScanReport(
            scan_id=scan_id,
            scan_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            target_path=str(self.target_path),
            total_files_scanned=len(py_files),
            total_dependencies_found=total_deps,
            installed_dependencies_count=len(detected_list),
            missing_dependencies_count=len(missing_list),
            integrity_hash=integrity_hash,
            detected_dependencies=[asdict(d) for d in detected_list],
            missing_dependencies=[asdict(m) for m in missing_list],
            scan_errors=self.scan_errors,
            compliance_status=compliance_status,
        )

    def export_json(self, report: ASTScanReport, output_path: Path) -> None:
        """Exporta los hallazgos en formato JSON normalizado."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Informe AST JSON exportado en: {output_path}")

    def export_markdown(self, report: ASTScanReport, output_path: Path) -> None:
        """Exporta el reporte ejecutivo en Markdown."""
        status_badge = "✅ CADENA DE SUMINISTRO ALINEADA" if report.missing_dependencies_count == 0 else "⚠️ DEPENDENCIAS FALTANTES DETECTADAS"
        
        md_content = f"""# Informe de Auditoría AST de Dependencias (ENS Alto / NIS2 / DORA)

**ID Escaneo:** `{report.scan_id}`  
**Ruta Escaneada:** `{report.target_path}`  
**Fecha de Análisis:** {report.scan_timestamp}  
**Estado Compliance:** {status_badge}  
**Hash de Integridad:** `{report.integrity_hash[:16]}...`  

---

## 1. Resumen de Análisis Sintáctico AST

- **Archivos `.py` Analizados:** {report.total_files_scanned}
- **Total Dependencias Detectadas:** {report.total_dependencies_found}
- **Dependencias Instaladas y Verificadas:** {report.installed_dependencies_count}
- **Dependencias Faltantes / No Instaladas:** {report.missing_dependencies_count} ⚠️
- **Errores de Lectura/Sintaxis:** {len(report.scan_errors)}

---

## 2. Dependencias No Instaladas (Riesgo en Cadena de Suministro)

"""
        if report.missing_dependencies_count == 0:
            md_content += "✅ **Todas las dependencias de terceros importadas en el código están instaladas en el entorno.**\n"
        else:
            md_content += "| Módulo Importado | Paquete PyPI Sugerido | Archivos donde se usa |\n"
            md_content += "|------------------|-----------------------|-----------------------|\n"
            for item in report.missing_dependencies:
                files_str = ", ".join([f"`{f}`" for f in item['source_files'][:3]])
                if len(item['source_files']) > 3:
                    files_str += f" (+{len(item['source_files'])-3} más)"
                md_content += f"| `{item['module_name']}` | **{item['pypi_package_name']}** | {files_str} |\n"

        md_content += """

---

## 3. Dependencias Instaladas Verificadas

| Módulo Importado | Paquete PyPI | Ocurrencias en Código |
|------------------|--------------|-----------------------|
"""
        for item in report.detected_dependencies:
            md_content += f"| `{item['module_name']}` | `{item['pypi_package_name']}` | {len(item['source_files'])} archivos |\n"

        md_content += f"""

---

## 4. Marco Normativo Aplicable

> **ENS (Nivel Alto) Art. 12 & NIS2 Art. 21(2)(d):** Exigen la identificación completa del software
> de terceros en producción, la comprobación de integridad y el control de dependencias para evitar
> ataques a la cadena de suministro (*Supply Chain Attacks*).

---
*Generado por `ast_scan.py` el {report.scan_timestamp}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Informe AST Markdown exportado en: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Escáner AST Autónomo de Dependencias Python (ENS Alto Art. 12 / NIS2 Art. 21 / DORA Art. 28)."
    )
    parser.add_argument(
        "-p",
        "--path",
        type=Path,
        default=Path("."),
        help="Ruta al directorio o archivo Python a analizar (default: directorio actual).",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("./ast_audit_reports"),
        help="Directorio donde se guardarán los informes JSON y Markdown.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "both"],
        default="both",
        help="Formato del informe generado (default: both).",
    )

    args = parser.parse_args()

    try:
        scanner = ASTDependencyScanner(args.path)
        report = scanner.scan()

        out_json = args.output_dir / f"{report.scan_id}_ast_report.json"
        out_md = args.output_dir / f"{report.scan_id}_ast_report.md"

        if args.format in ("json", "both"):
            scanner.export_json(report, out_json)
        if args.format in ("markdown", "both"):
            scanner.export_markdown(report, out_md)

        # Salida por consola resumida
        print(f"AST Scan Completed. Files: {report.total_files_scanned}, Dependencies: {report.total_dependencies_found}, Missing: {report.missing_dependencies_count}")
        
        if report.missing_dependencies_count > 0:
            sys.exit(1)
        sys.exit(0)

    except Exception as e:
        logger.critical(f"Error fatal durante el análisis AST: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
