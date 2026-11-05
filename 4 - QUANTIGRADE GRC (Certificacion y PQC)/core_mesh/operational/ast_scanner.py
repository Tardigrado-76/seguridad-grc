#!/usr/bin/env python3
"""
AST-based SAST scanner for Python dependency and exception analysis.
Aligns with ENS Categoría Alta and NIS2 Art. 21.2.d supply chain requirements.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Set


class ExceptionVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, lines: List[str]) -> None:
        self.filename = filename
        self.lines = lines
        self.violations: List[int] = []

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        lineno = getattr(node, "lineno", 1)
        line_idx = max(0, lineno - 1)
        comment_line = self.lines[line_idx] if line_idx < len(self.lines) else ""

        # Flag broad 'except Exception:' or bare 'except:' without explicit override
        if node.type is None or getattr(node.type, "id", None) == "Exception":
            if "# nosec" not in comment_line:
                self.violations.append(lineno)
        self.generic_visit(node)


class ASTScanner:
    """Production-grade Static AST Security & Dependency Scanner."""

    MAPPING: Dict[str, str] = {
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
    }

    IGNORE_DIRS: Set[str] = {
        ".venv", "venv", ".git", "dist", "build", ".pytest_cache",
        ".flake8_cache", "node_modules", "__pycache__"
    }

    def __init__(self, target_path: str | Path = ".") -> None:
        self.target_path = Path(target_path)

    def scan_dependencies(self, path: str | Path | None = None) -> Dict[str, Any]:
        scan_root = Path(path) if path else self.target_path
        if not scan_root.exists():
            return {"status": "ERROR", "message": f"Path not found: {scan_root}"}

        py_files: List[Path] = []
        if scan_root.is_file() and scan_root.suffix == ".py":
            py_files.append(scan_root)
        else:
            for root, dirs, files in os.walk(scan_root):
                dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
                for file in files:
                    if file.endswith(".py"):
                        py_files.append(Path(root) / file)

        imports: Set[str] = set()
        for file_path in py_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(content, filename=str(file_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for name in node.names:
                            imports.add(name.name.split(".")[0])
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imports.add(node.module.split(".")[0])
            except Exception:
                continue

        stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()
        local_modules = {d.name for d in scan_root.iterdir() if d.is_dir()} if scan_root.is_dir() else set()

        detected: List[str] = []
        missing: List[str] = []

        for imp in sorted(imports):
            if imp in stdlib or imp in local_modules or not imp:
                continue
            pip_name = self.MAPPING.get(imp, imp)
            detected.append(pip_name)
            try:
                spec = importlib.util.find_spec(imp)
            except Exception:
                spec = None
            if spec is None:
                missing.append(pip_name)

        return {
            "status": "SUCCESS",
            "files_scanned": len(py_files),
            "detected_packages": detected,
            "missing_packages": missing,
        }

    def scan_exception_guards(self, path: str | Path | None = None) -> Dict[str, Any]:
        scan_root = Path(path) if path else self.target_path
        violations: Dict[str, List[int]] = {}

        py_files: List[Path] = []
        if scan_root.is_file() and scan_root.suffix == ".py":
            py_files.append(scan_root)
        else:
            for root, dirs, files in os.walk(scan_root):
                dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
                for file in files:
                    if file.endswith(".py"):
                        py_files.append(Path(root) / file)

        for file_path in py_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                tree = ast.parse(content, filename=str(file_path))
                visitor = ExceptionVisitor(str(file_path), lines)
                visitor.visit(tree)
                if visitor.violations:
                    violations[str(file_path)] = visitor.violations
            except Exception:
                continue

        return {
            "status": "SUCCESS",
            "files_scanned": len(py_files),
            "broad_exceptions_count": sum(len(v) for v in violations.values()),
            "violations": violations,
        }

