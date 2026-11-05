<#
.SYNOPSIS
    Suite de Pruebas de Ingeniería del Caos y Resiliencia para software en Windows.
    Cumplimiento: ENS Alta / DORA / NIS2.
#>

[CmdletBinding()]
param (
    [Parameter(HelpMessage = "Ruta absoluta al binario ejecutable bajo prueba.")]
    [string]$BinPath = "build/fastapi_server.exe",

    [Parameter(HelpMessage = "Ruta al archivo de configuración de SoftHSM.")]
    [string]$SoftHsmConf = "C:\SoftHSM2\etc\softhsm2.conf",

    [Parameter(HelpMessage = "Nombre del proceso del servicio ejecutándose.")]
    [string]$ProcessName = "fastapi_server"
)

$ErrorActionPreference = "Stop"
$SOFTHSM_BAK = "$SoftHsmConf.bak"

function Write-Header([string]$text) {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host " [CHAOS TEST] $text" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
}

# --- VALIDACION INICIAL ---
if (-not (Test-Path $BinPath)) {
    Write-Error "No se encuentra el binario compilado en $BinPath."
}

Write-Header "INICIANDO SUITE DE INGENIERÍA DEL CAOS INDEPENDIENTE"

# =====================================================================
# PRUEBA 1: FALLO CATASTROFICO HSM
# =====================================================================
Write-Header "Prueba 1: Pérdida de Hardware Criptográfico (HSM)"

if (Test-Path $SoftHsmConf) {
    Write-Host "[*] Simulando desconexión de hardware (Ocultando config)..." -ForegroundColor Yellow
    Rename-Item -Path $SoftHsmConf -NewName (Split-Path $SOFTHSM_BAK -Leaf)
    
    try {
        Write-Host "[*] Lanzando petición HTTP al endpoint criptográfico (localhost)..." -ForegroundColor Gray
        $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/verify" -Method Post -Body '{"token": "test"}' -TimeoutSec 5
        Write-Host "[!] ERROR: El servidor respondió normalmente o no controló el fallo." -ForegroundColor Red
    } 
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 503) {
            Write-Host "[+] ÉXITO: El servidor resistió el fallo y devolvió 503 Service Unavailable." -ForegroundColor Green
        } else {
            Write-Host "[!] COMPORTAMIENTO ANÓMALO: Código de estado recibido: $statusCode" -ForegroundColor Orange
        }
    }
    finally {
        Write-Host "[*] Restaurando hardware (Restaurando config)..." -ForegroundColor Gray
        if (Test-Path $SOFTHSM_BAK) {
            Rename-Item -Path $SOFTHSM_BAK -NewName (Split-Path $SoftHsmConf -Leaf)
        }
    }
} else {
    Write-Host "[----] SoftHSM2 no detectado en la ruta especificada. Saltando prueba criptográfica." -ForegroundColor DarkGray
}

# =====================================================================
# PRUEBA 2: INTEGRIDAD DEL BINARIO (SLSA L4)
# =====================================================================
Write-Header "Prueba 2: Violación de Integridad del Binario (SLSA L4)"

$binName = Split-Path $BinPath -Leaf
Write-Host "[*] Creando copia de seguridad del binario original..." -ForegroundColor Gray
Copy-Item $BinPath "$BinPath.orig" -Force

try {
    Write-Host "[*] Corrompiendo deliberadamente el primer byte del ejecutable..." -ForegroundColor Yellow
    $bytes = [System.IO.File]::ReadAllBytes($BinPath)
    $bytes[0] = 0x00 
    [System.IO.File]::WriteAllBytes($BinPath, $bytes)

    Write-Host "[*] Ejecutando cosign verify-blob..." -ForegroundColor Gray
    cosign verify-blob --key cosign.pub --signature "$BinPath.sig" $BinPath 2>$null
    
    Write-Host "[!] ERROR: ¡Cosign aceptó el binario modificado!" -ForegroundColor Red
} 
catch {
    Write-Host "[+] ÉXITO: Cosign rechazó el binario corrupto. Firma inválida detectada." -ForegroundColor Green
}
finally {
    Write-Host "[*] Restaurando binario legítimo original..." -ForegroundColor Gray
    if (Test-Path "$BinPath.orig") {
        if (Test-Path $BinPath) { Remove-Item $BinPath -Force }
        Rename-Item "$BinPath.orig" $binName
    }
}

# =====================================================================
# PRUEBA 3: SIMULACIÓN DE INTRUSIÓN EN RUNTIME
# =====================================================================
Write-Header "Prueba 3: Intrusión en Runtime (Dumping de Memoria)"

$proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Host "[!] Salto de prueba: El proceso '$ProcessName' debe estar ejecutándose para auditarlo." -ForegroundColor Orange
} else {
    Write-Host "[*] Proceso detectado con PID: $($proc.Id)" -ForegroundColor Gray
    Write-Host "[*] Lanzando Procdump para forzar la lectura de RAM..." -ForegroundColor Yellow
    
    try {
        Start-Process -FilePath "procdump.exe" -ArgumentList "-ma $($proc.Id) dump.dmp" -NoNewWindow -Wait
        Start-Sleep -Seconds 1
        
        if (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue) {
            Write-Host "[!] ERROR: El proceso sobrevivió al volcado. El runtime supervisor falló." -ForegroundColor Red
        } else {
            Write-Host "[+] ÉXITO: El proceso fue mitigado instantáneamente por el supervisor al detectar la lectura." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[-] Error al ejecutar Procdump. Asegúrate de tener procdump.exe en el PATH." -ForegroundColor Red
    }
}

Write-Header "SUITE FINALIZADA"
"