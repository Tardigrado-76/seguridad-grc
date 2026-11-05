#!/usr/bin/env python3
"""Verificador exhaustivo de rutas del path_registry.

Itera todas las constantes Path de path_registry.py y genera un reporte
con el estado de cada ruta (existe, no existe, directorio vacio).
"""

import sys
from pathlib import Path

# Asegurar que el directorio de la plataforma esta en sys.path
PLATFORM_DIR = Path(__file__).resolve().parent
if str(PLATFORM_DIR) not in sys.path:
    sys.path.insert(0, str(PLATFORM_DIR))

import path_registry


def verify_all_paths() -> list[dict]:
    """Verifica todas las constantes Path en path_registry.

    Returns:
        Lista de dicts con name, path, status, detail.
    """
    results: list[dict] = []
    for name in sorted(dir(path_registry)):
        if name.startswith("_"):
            continue
        val = getattr(path_registry, name)
        if not isinstance(val, Path):
            continue

        entry = {"name": name, "path": str(val)}
        if val.is_file():
            entry["status"] = "OK_FILE"
            entry["detail"] = f"{val.stat().st_size} bytes"
        elif val.is_dir():
            children = list(val.iterdir())
            if children:
                entry["status"] = "OK_DIR"
                entry["detail"] = f"{len(children)} items"
            else:
                entry["status"] = "WARN_EMPTY"
                entry["detail"] = "Directorio vacio"
        else:
            entry["status"] = "ERR_MISSING"
            entry["detail"] = "No encontrado"

        results.append(entry)
    return results


def generate_report(results: list[dict]) -> str:
    """Genera reporte Markdown con los resultados."""
    lines = [
        "# Verificacion de Rutas - path_registry.py",
        "",
        f"Total constantes Path: **{len(results)}**",
        "",
        "| Estado | Constante | Ruta | Detalle |",
        "|--------|-----------|------|---------|",
    ]
    status_icons = {
        "OK_FILE": "OK",
        "OK_DIR": "OK",
        "WARN_EMPTY": "WARN",
        "ERR_MISSING": "ERR",
    }
    for r in results:
        icon = status_icons.get(r["status"], "?")
        lines.append(f"| {icon} | `{r['name']}` | `{r['path']}` | {r['detail']} |")

    # Resumen
    ok = sum(1 for r in results if r["status"].startswith("OK"))
    warn = sum(1 for r in results if r["status"].startswith("WARN"))
    err = sum(1 for r in results if r["status"].startswith("ERR"))
    lines.extend([
        "",
        "## Resumen",
        f"- OK: {ok}",
        f"- Advertencias: {warn}",
        f"- Errores: {err}",
        f"- Total: {len(results)}",
    ])
    return "\n".join(lines)


if __name__ == "__main__":
    results = verify_all_paths()
    report = generate_report(results)
    print(report)

    # Guardar en REPORTS
    reports_dir = Path(r"E:\PROYECTOS IA\AUDITORIAS\COMPILANCE_PLATFORM\REPORTS")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "path_verification_report.md"
    report_file.write_text(report, encoding="utf-8")
    print(f"\nReporte guardado en: {report_file}")

    # Exit code basado en errores
    err_count = sum(1 for r in results if r["status"].startswith("ERR"))
    sys.exit(1 if err_count > 0 else 0)
