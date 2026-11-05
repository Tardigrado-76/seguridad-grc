#Requires -Version 7.0
# BUNKEROS — CSS AOT Build Script
# Genera bunker.css minificado y calcula SRI SHA-384

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ROOT    = Split-Path $PSScriptRoot -Parent
$INPUT   = Join-Path $ROOT 'src\css\base.css'
$OUTPUT  = Join-Path $ROOT 'src\static\css\bunker.css'
$CONFIG  = Join-Path $ROOT 'tailwind.config.js'

Write-Host '[BunkerOS] Compilando Tailwind AOT...' -ForegroundColor Cyan

# 1. Compilar + minificar
npx tailwindcss `
  --input  $INPUT `
  --output $OUTPUT `
  --config $CONFIG `
  --minify

if ($LASTEXITCODE -ne 0) {
  Write-Error '[FAIL] Tailwind compilation failed'
  exit 1
}

# 2. Calcular SRI SHA-384
$bytes  = [System.IO.File]::ReadAllBytes($OUTPUT)
$sha384 = [System.Security.Cryptography.SHA384]::Create()
$hash   = $sha384.ComputeHash($bytes)
$b64    = [Convert]::ToBase64String($hash)
$sri    = "sha384-$b64"

# 3. Escribir hash en archivo para inyección en FastAPI
$sriFile = Join-Path $ROOT 'src\static\css\bunker.css.sri'
Set-Content -Path $sriFile -Value $sri -Encoding UTF8

Write-Host "[OK] CSS compilado: $OUTPUT" -ForegroundColor Green
Write-Host "[OK] SRI hash: $sri"         -ForegroundColor Green
