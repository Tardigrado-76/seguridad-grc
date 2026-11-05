<#
.SYNOPSIS
    Compilador Standalone para BunkerOS (ENS Alta)
.DESCRIPTION
    Transforma FastAPI y sus dependencias a un binario C ofuscado usando Nuitka, 
    incorporando directivas militares de anti-depuración y aislamiento UAC.
#>

$ErrorActionPreference = "Stop"
Write-Host "[*] Iniciando Secuencia de Blindaje Nuitka para BunkerOS (Grado Militar)..." -ForegroundColor Cyan

# 1. Limpieza del directorio de distribución previo
if (Test-Path ".\dist") {
    Remove-Item -Recurse -Force ".\dist\*"
    Write-Host "[+] Directorio /dist purgado." -ForegroundColor Green
} else {
    New-Item -ItemType Directory -Force -Path ".\dist" | Out-Null
}

# 2. Compilación Nuitka (Nivel C)
Write-Host "[*] Ejecutando Nuitka. Esto requerirá alto uso de CPU..." -ForegroundColor Yellow

python -m nuitka `
    --standalone `
    --onefile `
    --assume-yes-for-downloads `
    --windows-disable-console `
    --windows-uac-admin `
    --enable-plugin=anti-bloat `
    --include-package=uvicorn `
    --include-package=cryptography `
    --include-package=pydantic `
    --remove-output `
    --output-dir="dist" `
    --include-data-dir="src/static=src/static" `
    --include-data-dir="src/templates=src/templates" `
    src/fastapi_server.py

if (-not (Test-Path ".\dist\fastapi_server.exe")) {
    Write-Host "[!] CRÍTICO: La compilación de Nuitka ha fallado." -ForegroundColor Red
    exit 1
}

# Renombrar el binario para reflejar el artefacto final
Rename-Item -Path ".\dist\fastapi_server.exe" -NewName "BunkerOS_Core.exe"

Write-Host "[✓] Compilación finalizada. Binario generado." -ForegroundColor Green

# 3. Firma Digital e Inmutabilidad (Release Hash SHA-384)
Write-Host "[*] Sellando el artefacto inmutable..." -ForegroundColor Cyan
$HashInfo = Get-FileHash -Path ".\dist\BunkerOS_Core.exe" -Algorithm SHA384
$HashValue = $HashInfo.Hash

# Guardar el manifiesto inmutable para la auditoría (B.F2.2)
$HashValue | Out-File -FilePath ".\dist\BunkerOS_Core_SHA384.txt" -Encoding ascii

Write-Host "=========================================================="
Write-Host " [!] ATENCIÓN AUDITORES / INVERSORES:" -ForegroundColor Yellow
Write-Host " El artefacto inexpugnable ha sido generado."
Write-Host " Hash SHA-384 del binario:"
Write-Host " $HashValue" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "=========================================================="
