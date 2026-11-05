<#
============================================================================
 AUDIT_CONSOLE — LAUNCHER CONJUNTO (Backend FastAPI + Frontend Next.js)
 ----------------------------------------------------------------------------
 - Setup automático de primera ejecución:
     * Crea el venv del backend e instala requirements.txt si es necesario.
     * Crea backend/.env desde .env.example si no existe.
     * Verifica node_modules del frontend (npm install si falta).
 - Arranca ambos procesos con logs separados en ./logs/.
 - Detecta el health-check del backend y abre el navegador en el dashboard.
 - Al salir (Ctrl+C / cierre de ventana) mata AMBOS procesos.
 Uso:
     powershell -ExecutionPolicy Bypass -File .\start_audit_console.ps1 [-SkipInstall] [-NoBrowser]
============================================================================
#>

param(
    [switch]$SkipInstall,   # Omitir instalación de dependencias
    [switch]$NoBrowser,     # No abrir el navegador automáticamente
    [int]$Port = 3000       # Puerto del frontend (Next.js)
)

$ErrorActionPreference = "Stop"
$Root        = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir  = Join-Path $Root "backend"
$FrontendDir = Join-Path $Root "frontend"
$LogDir      = Join-Path $Root "logs"
$VenvPython  = Join-Path $BackendDir "venv\Scripts\python.exe"
$BackendPort = 8000
$FrontendPort = $Port
$BackendUrl  = "http://127.0.0.1:$BackendPort"
$FrontendUrl = "http://127.0.0.1:$FrontendPort"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Write-Step([string]$msg) {
    Write-Host "`n[$([DateTime]::Now.ToString('HH:mm:ss'))] $msg" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  AUDIT_CONSOLE — BUNKEROS SECURITY DASHBOARD v1.0" -ForegroundColor Cyan
Write-Host "  Backend: $BackendUrl  |  Frontend: $FrontendUrl" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------ 0. LIMPIEZA DE PUERTOS
function Free-Port([int]$TargetPort) {
    try {
        $connections = Get-NetTCPConnection -LocalPort $TargetPort -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            $procId = $conn.OwningProcess
            if ($procId -gt 0 -and $procId -ne $PID) {
                Write-Host "  [!] Liberando puerto $TargetPort ocupado por PID $procId..." -ForegroundColor Yellow
                Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            }
        }
    } catch { }

    # Fallback con netstat para máxima robustez
    try {
        $lines = netstat -ano | Select-String ":$TargetPort\s"
        foreach ($line in $lines) {
            $parts = $line.ToString().Trim() -split '\s+'
            $pidToKill = $parts[-1]
            if ($pidToKill -match '^\d+$' -and [int]$pidToKill -ne $PID -and [int]$pidToKill -gt 0) {
                Stop-Process -Id [int]$pidToKill -Force -ErrorAction SilentlyContinue
            }
        }
    } catch { }
}

Write-Step "Verificando puertos $BackendPort y $FrontendPort..."
Free-Port $BackendPort
Free-Port $FrontendPort
Start-Sleep -Milliseconds 500

# ---------------------------------------------------------------- 1. BACKEND
if (-not $SkipInstall) {
    if (-not (Test-Path $VenvPython)) {
        Write-Step "Creando virtualenv del backend..."
        Push-Location $BackendDir
        try { python -m venv venv | Out-Null } finally { Pop-Location }
    }

    # Instalar dependencias SOLO si faltan (verificación rápida de import)
    & $VenvPython -c "import fastapi, uvicorn, sse_starlette, aiohttp, cryptography" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Step "Instalando dependencias del backend (requirements.txt)..."
        & $VenvPython -m pip install --disable-pip-version-check -q -r (Join-Path $BackendDir "requirements.txt")
        if ($LASTEXITCODE -ne 0) { Write-Error "Fallo instalando dependencias del backend." }
    } else {
        Write-Step "Dependencias del backend ya instaladas."
    }
}

# .env del backend
if (-not (Test-Path (Join-Path $BackendDir ".env"))) {
    if (Test-Path (Join-Path $BackendDir ".env.example")) {
        Copy-Item (Join-Path $BackendDir ".env.example") (Join-Path $BackendDir ".env")
        Write-Step "Creado backend/.env desde .env.example (revisa los valores)."
    }
}

# --------------------------------------------------------------- 2. FRONTEND
if (-not $SkipInstall) {
    if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
        Write-Step "Instalando dependencias del frontend (npm install)..."
        Push-Location $FrontendDir
        try { npm install --no-audit --no-fund | Out-Null } finally { Pop-Location }
    } else {
        Write-Step "node_modules del frontend presente."
    }
}

# ------------------------------------------------------------ 3. ARRANQUE
Write-Step "Arrancando BACKEND (FastAPI) en $BackendUrl ..."
$BackendCmdLine = "-m uvicorn main:app --host 127.0.0.1 --port $BackendPort --app-dir `"$BackendDir`" --log-level info"
$BackendProc = Start-Process -FilePath $VenvPython -ArgumentList $BackendCmdLine `
  -WorkingDirectory $BackendDir -RedirectStandardOutput (Join-Path $LogDir "backend.log") `
  -RedirectStandardError (Join-Path $LogDir "backend.err.log") -PassThru -NoNewWindow

Write-Step "Arrancando FRONTEND (Next.js) en $FrontendUrl ..."
$FrontendProc = Start-Process -FilePath "cmd.exe" -ArgumentList @(
    "/c", "npm run dev -- -p $FrontendPort"
) -WorkingDirectory $FrontendDir -RedirectStandardOutput (Join-Path $LogDir "frontend.log") `
  -RedirectStandardError (Join-Path $LogDir "frontend.err.log") -PassThru -NoNewWindow

# Health check del backend (máx. 60s)
Write-Step "Esperando health-check del backend..."
$backendHealthy = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 1
    if ($BackendProc.HasExited) { break }
    try {
        $resp = Invoke-WebRequest -Uri "$BackendUrl/api/v1/health" -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) { $backendHealthy = $true; break }
    } catch { }
}
if ($backendHealthy) {
    Write-Host "  [OK] Backend saludable: $BackendUrl/api/v1/health" -ForegroundColor Green
} else {
    Write-Host "  [!] No se confirmó el health-check. Revisa logs/backend.err.log" -ForegroundColor Yellow
}

# Health check del frontend (máx. 90s — primera compilación Next puede tardar)
Write-Step "Esperando el frontend en $FrontendUrl ..."
$frontendHealthy = $false
for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 1
    if ($FrontendProc.HasExited) { break }
    try {
        $resp = Invoke-WebRequest -Uri $FrontendUrl -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) { $frontendHealthy = $true; break }
    } catch { }
}
if ($frontendHealthy) {
    Write-Host "  [OK] Frontend respondiendo: $FrontendUrl" -ForegroundColor Green
} else {
    Write-Host "  [!] El frontend no respondió. Revisa logs/frontend.err.log" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Dashboard:  $FrontendUrl" -ForegroundColor Green
Write-Host "  API Docs:   $BackendUrl/api/docs" -ForegroundColor Green
Write-Host "  Logs:       $LogDir" -ForegroundColor DarkGray
Write-Host "  Ctrl+C para detener backend y frontend." -ForegroundColor DarkGray
Write-Host ""

if (-not $NoBrowser -and $frontendHealthy) {
    Start-Process $FrontendUrl
}

# Espera y limpieza al salir
try {
    Wait-Process -Id $BackendProc.Id, $FrontendProc.Id -ErrorAction SilentlyContinue
} finally {
    Write-Step "Deteniendo procesos..."
    foreach ($p in @($BackendProc, $FrontendProc)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    # El frontend corre bajo cmd.exe; matar el árbol de node
    Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$FrontendDir*" -or $_.CommandLine -like "*next*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    
    # Liberar puertos por seguridad
    Free-Port $BackendPort
    Free-Port $FrontendPort
    Write-Host "  Procesos detenidos y puertos liberados. Logs en $LogDir" -ForegroundColor DarkGray
}

