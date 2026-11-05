<#
.SYNOPSIS
    Suite de Pruebas de Ingenieria del Caos y Resiliencia para BunkerOS.
    Cumplimiento: ENS Alta / DORA / NIS2.
#>

$ErrorActionPreference = "Stop"
$BIN_PATH = "build/fastapi_server.exe"
$SOFTHSM_CONF = "C:\SoftHSM2\etc\softhsm2.conf"
$SOFTHSM_BAK = "C:\SoftHSM2\etc\softhsm2.conf.bak"

function Write-Header([string]$text) {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host " [CHAOS TEST] $text" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
}

# --- VALIDACION INICIAL ---
if (-not (Test-Path $BIN_PATH)) {
    Write-Error "No se encuentra el binario compilado en $BIN_PATH. Compila primero con Nuitka."
}

Write-Header "INICIANDO SUITE DE INGENIERIA DEL CAOS: BUNKEROS"

# =====================================================================
# PRUEBA 1: FALLO CATASTROFICO HSM
# =====================================================================
Write-Header "Prueba 1: Perdida de Hardware Criptografico (HSM)"

if (Test-Path $SOFTHSM_CONF) {
    Write-Host "[*] Simulando desconexion de hardware (Ocultando softhsm2.conf)..." -ForegroundColor Yellow
    Rename-Item -Path $SOFTHSM_CONF -NewName "softhsm2.conf.bak"
    
    try {
        Write-Host "[*] Lanzando peticion HTTP al endpoint criptografico..." -ForegroundColor Gray
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/verify" -Method Post -Body '{"token": "test"}' -TimeoutSec 5
        Write-Host "[!] ERROR: El servidor respondio normalmente o no controlo el fallo." -ForegroundColor Red
    } 
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 503) {
            Write-Host "[+] EXITO: El servidor resistio el fallo y devolvio 503 Service Unavailable." -ForegroundColor Green
        } else {
            Write-Host "[!] COMPORTAMIENTO ANOMALO: Codigo de estado recibido: $statusCode" -ForegroundColor Orange
        }
    }
    finally {
        Write-Host "[*] Restaurando hardware (Restaurando softhsm2.conf)..." -ForegroundColor Gray
        if (Test-Path $SOFTHSM_BAK) {
            Rename-Item -Path $SOFTHSM_BAK -NewName "softhsm2.conf"
        }
    }
} else {
    Write-Host "[----] SoftHSM2 no detectado en la ruta por defecto. Saltando mutacion de archivo." -ForegroundColor DarkGray
}

# =====================================================================
# PRUEBA 2: EMPAREJAMIENTO SLSA L4 (INTEGRIDAD)
# =====================================================================
Write-Header "Prueba 2: Violacion de Integridad del Binario (SLSA L4)"

Write-Host "[*] Creando copia de seguridad del binario original..." -ForegroundColor Gray
Copy-Item $BIN_PATH "$BIN_PATH.orig" -Force

try {
    Write-Host "[*] Corrompiendo deliberadamente el primer byte del ejecutable..." -ForegroundColor Yellow
    $bytes = [System.IO.File]::ReadAllBytes($BIN_PATH)
    $bytes[0] = 0x00 
    [System.IO.File]::WriteAllBytes($BIN_PATH, $bytes)

    Write-Host "[*] Ejecutando cosign verify-blob..." -ForegroundColor Gray
    cosign verify-blob --key cosign.pub --signature "$BIN_PATH.sig" $BIN_PATH 2>$null
    
    Write-Host "[!] ERROR: ¡Cosign acepto el binario modificado!" -ForegroundColor Red
} 
catch {
    Write-Host "[+] EXITO: Cosign rechazo el binario corrupto. Firma invalida detectada." -ForegroundColor Green
}
finally {
    Write-Host "[*] Restaurando binario legitimo original..." -ForegroundColor Gray
    if (Test-Path "$BIN_PATH.orig") {
        if (Test-Path $BIN_PATH) { Remove-Item $BIN_PATH -Force }
        Rename-Item "$BIN_PATH.orig" "fastapi_server.exe"
    }
}

# =====================================================================
# PRUEBA 3: SIMULACION DE INTRUSION EN RUNTIME
# =====================================================================
Write-Header "Prueba 3: Intrusion en Runtime (Dumping de Memoria)"

$proc = Get-Process -Name "fastapi_server" -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Host "[!] Salto de prueba: El proceso 'fastapi_server' debe estar ejecutandose para atacarlo." -ForegroundColor Orange
} else {
    Write-Host "[*] Proceso BunkerOS detectado con PID: $($proc.Id)" -ForegroundColor Gray
    Write-Host "[*] Lanzando Procdump para forzar la lectura indebida de RAM..." -ForegroundColor Yellow
    
    try {
        Start-Process -FilePath "procdump.exe" -ArgumentList "-ma $($proc.Id) dump.dmp" -NoNewWindow -Wait
        Start-Sleep -Seconds 1
        
        if (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue) {
            Write-Host "[!] ERROR: El proceso sobrevivio al volcado. El Runtime Guard fallo." -ForegroundColor Red
        } else {
            Write-Host "[+] EXITO: El proceso fue mitigado instantaneamente por el supervisor." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[-] Error al ejecutar Procdump. Asegurate de que procdump.exe esta en el PATH o en la carpeta actual." -ForegroundColor Red
    }
}

Write-Header "SUITE FINALIZADA"