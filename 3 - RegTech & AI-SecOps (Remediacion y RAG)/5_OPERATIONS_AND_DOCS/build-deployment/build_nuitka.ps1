#Requires -Version 5.1
# =============================================================================
# build_nuitka.ps1 - Compilacion Hardened de Grado Produccion para BunkerOS
# Generado automaticamente por reparar_pipeline_nuitka.ps1
# =============================================================================

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Compilacion BunkerOS con Nuitka (Standalone)"     -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

# Interprete Python del sistema (sin Hermes, sin venv externo)
# Resolucion dinamica: usa el Python del sistema, filtrando rutas Hermes
$PythonCmd = $null
$candidatos = @(
    "C:\Users\josel\AppData\Local\Programs\Python\Python313\python.exe",
    "$env:USERPROFILE\AppData\Local\Programs\Python\Python313\python.exe",
    "$env:USERPROFILE\AppData\Local\Programs\Python\Python312\python.exe",
    "$env:USERPROFILE\AppData\Local\Programs\Python\Python311\python.exe"
)
foreach ($c in $candidatos) {
    if ((Test-Path $c -PathType Leaf) -and ($c -notmatch "hermes")) {
        $PythonCmd = $c; break
    }
}
if ($null -eq $PythonCmd) {
    Write-Host "[!] No se encontro Python legitimo. Ejecuta reparar_pipeline_nuitka.ps1" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Python: $PythonCmd" -ForegroundColor Green

# ---- Verificacion de Nuitka ----
try {
    Write-Host "[*] Verificando Nuitka..." -ForegroundColor Yellow
    & $PythonCmd -m nuitka --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Nuitka no disponible (exit $LASTEXITCODE)." }
    Write-Host "[+] Nuitka listo." -ForegroundColor Green
}
catch {
    Write-Host "[!] Nuitka no responde: $_" -ForegroundColor Red
    Write-Host "    Ejecuta: reparar_pipeline_nuitka.ps1" -ForegroundColor Red
    exit 1
}

# ---- Compilacion Nuitka (flags militares) ----
try {
    Write-Host "[*] Compilando src/fastapi_server.py..." -ForegroundColor Yellow
    & $PythonCmd -m nuitka `
        --standalone `
        --onefile `
        --remove-output `
        --assume-yes-for-downloads `
        --windows-console-mode=disable `
        --lto=yes `
        --clean-cache=all `
        --disable-cache=all `
        --include-package=pkcs11 `
        --include-package=authlib `
        --include-package=cachetools `
        --output-dir=dist `
        src/fastapi_server.py

    if ($LASTEXITCODE -ne 0) { throw "Nuitka devolvio codigo de error: $LASTEXITCODE" }
    Write-Host "[+] Compilacion completada. Binario en: dist\" -ForegroundColor Green
}
catch {
    Write-Host "[!] Fallo en compilacion Nuitka: $_" -ForegroundColor Red
    exit 1
}
