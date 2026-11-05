"""
Test Suite for CCN-CERT CLARA Hardening & Remediation Suite (ENS / NIS2 / CRA).
Validates PowerShell AST syntax, CLI parameter parsing, DryRun execution,
Audit log generation, and Rollback safety invariants.
"""
import subprocess
import tempfile
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_powershell_scripts_syntax() -> None:
    """Verifies that all PowerShell scripts (.ps1) in the repository have valid AST syntax without parse errors."""
    ps_scripts = list(REPO_ROOT.rglob("*.ps1"))
    assert len(ps_scripts) >= 5, f"Expected at least 5 .ps1 scripts, found {len(ps_scripts)}"

    for script in ps_scripts:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"""
            $errors = $null
            $tokens = $null
            [System.Management.Automation.Language.Parser]::ParseFile('{script}', [ref]$tokens, [ref]$errors)
            if ($errors.Count -gt 0) {{
                $errors | ForEach-Object {{ Write-Error $_.Message }}
                exit 1
            }} else {{
                exit 0
            }}
            """,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"Script {script.name} has syntax errors: {result.stderr}"


def test_invoke_clara_hardening_dryrun_alto(tmp_path: Path) -> None:
    """Verifies that Invoke-ClaraHardening.ps1 executes successfully in -DryRun mode without admin elevation."""
    log_file = tmp_path / "clara_test_alto.log"
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(REPO_ROOT / "Invoke-ClaraHardening.ps1"),
        "-Tier",
        "Alto",
        "-DryRun",
        "-LogPath",
        str(log_file),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert result.returncode == 0, f"DryRun Alto failed: {result.stderr}\n{result.stdout}"
    assert log_file.exists(), "El log de auditoría debe generarse en la ruta especificada"
    log_content = log_file.read_text(encoding="utf-8", errors="ignore")
    assert "[SIMULACIÓN]" in log_content, "El log debe registrar las comprobaciones de simulación"
    assert "Simulación completada con éxito" in log_content


def test_invoke_clara_hardening_dryrun_medio(tmp_path: Path) -> None:
    """Verifies -DryRun for Tier Medio."""
    log_file = tmp_path / "clara_test_medio.log"
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(REPO_ROOT / "Invoke-ClaraHardening.ps1"),
        "-Tier",
        "Medio",
        "-DryRun",
        "-LogPath",
        str(log_file),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert result.returncode == 0
    assert log_file.exists()


def test_invoke_clara_hardening_invalid_tier() -> None:
    """Verifies that an invalid Tier parameter is rejected by PowerShell ValidateSet."""
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(REPO_ROOT / "Invoke-ClaraHardening.ps1"),
        "-Tier",
        "SuperInvalido",
        "-DryRun",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert result.returncode != 0, "Debe fallar al proporcionar un Tier que no está en ValidateSet"


def test_invoke_clara_rollback_missing_file() -> None:
    """Verifies that Invoke-ClaraRollback.ps1 aborts with code 1 if backup file does not exist."""
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(REPO_ROOT / "Invoke-ClaraRollback.ps1"),
        "-RestoreBackupFile",
        r"C:\archivo_de_backup_que_no_existe_12345.reg",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert result.returncode != 0
    assert "ERROR: No se encontro el archivo de respaldo" in result.stdout or result.returncode == 1


def test_clara_mitigation_catalog_integrity() -> None:
    """Verifies that the catalog markdown file exists and contains ENS/NIS2 mappings."""
    catalog_path = REPO_ROOT / "ccn-cert-clara-suite" / "CATALOGO_MITIGACION_ENS_NIS2.md"
    assert catalog_path.exists(), "El catálogo de mitigación ENS/NIS2 debe existir"
    content = catalog_path.read_text(encoding="utf-8")
    assert "RD 311/2022" in content
    assert "NIS2" in content
    assert "CLARA" in content

