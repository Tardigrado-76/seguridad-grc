Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ROOT = Split-Path $PSScriptRoot -Parent
$WASM_DIR = Join-Path $ROOT 'wasm'
$WAT_FILE = Join-Path $WASM_DIR 'bunker_jwt.wat'
$STATIC_DIR = Join-Path $ROOT 'src\static'
$STATIC_WASM_DIR = Join-Path $STATIC_DIR 'wasm'
$OUT_WASM = Join-Path $STATIC_WASM_DIR 'bunker_jwt.wasm'

if (!(Test-Path $STATIC_WASM_DIR)) { New-Item -ItemType Directory -Force -Path $STATIC_WASM_DIR | Out-Null }

Write-Host "[BunkerOS] Ensamblando WAT a WASM..." -ForegroundColor Cyan
# Requisito previo: Node.js y npx instalados. Descarga 'wabt' de forma temporal si no está instalado
$npxCmd = "npx --yes -p wabt wat2wasm `"$WAT_FILE`" -o `"$OUT_WASM`""
Invoke-Expression $npxCmd

if (!(Test-Path $OUT_WASM)) {
    throw "[SECURITY-GATE] Fallo al generar bunker_jwt.wasm"
}

# Calcular SRI del WASM (SHA-384)
$bytes  = [System.IO.File]::ReadAllBytes($OUT_WASM)
$sha384 = [System.Security.Cryptography.SHA384]::Create()
$b64    = [System.Convert]::ToBase64String($sha384.ComputeHash($bytes))
$wasmHash = "sha384-$b64"

Write-Host "[OK] WASM compilado. SRI: $wasmHash" -ForegroundColor Green

# Actualizar el .sri-manifest.json
$manifestPath = Join-Path $STATIC_DIR '.sri-manifest.json'
if (Test-Path $manifestPath) {
    $manifest = Get-Content $manifestPath | ConvertFrom-Json
    # Usamos Add-Member u asignación si ya existe
    if ($manifest.psobject.properties.match('wasm').Count) {
        $manifest.wasm = $wasmHash
    } else {
        $manifest | Add-Member -MemberType NoteProperty -Name "wasm" -Value $wasmHash
    }
    $manifest | ConvertTo-Json | Set-Content $manifestPath -Encoding UTF8
    Write-Host "[OK] .sri-manifest.json actualizado con hash WASM" -ForegroundColor Green
} else {
    Write-Host "[WARNING] .sri-manifest.json no encontrado, se requiere ejecutar download-alpine.ps1 primero" -ForegroundColor Yellow
}
