#Requires -RunAsAdministrator
<#
.SYNOPSIS
    BunkerOS Auto-Air-Gap Script (PowerShell / Windows)
    MITRE ATT&CK: T1562.004 - Impair Defenses: Disable or Modify System Firewall
    Invocado por IntrusionDetectionEngine cuando una IP no autorizada supera el umbral.

.PARAMETER MitreId
    Identificador MITRE ATT&CK que desencadenó el Air-Gap.

.PARAMETER AttackerIp
    Dirección IP del atacante a bloquear. Si está vacía, bloquea los puertos del servidor.

.EXAMPLE
    .\auto_air_gap.ps1 -MitreId "T1499" -AttackerIp "203.0.113.42"
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$MitreId = "UNKNOWN",

    [Parameter(Mandatory=$false)]
    [string]$AttackerIp = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Configuración ─────────────────────────────────────────────────────────────
$Timestamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir      = Join-Path $ScriptDir "..\logs"
$LogFile     = Join-Path $LogDir "air_gap_activations.log"
$BunkerPorts = @(8000, 8010, 8443)
$RuleName    = "BUNKER_AIR_GAP"

# ── Asegurar directorio de logs ───────────────────────────────────────────────
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-AirGapLog {
    param([string]$Message)
    $Entry = "[$Timestamp] $Message"
    Add-Content -Path $LogFile -Value $Entry -Encoding UTF8
    Write-Host "[BUNKER AIR-GAP] $Message"
}

Write-AirGapLog "T1562.004 - Air-Gap activado. MITRE: $MitreId | IP Atacante: $AttackerIp"

# ── Bloqueo por IP del atacante (prioritario) ─────────────────────────────────
if ($AttackerIp -ne "" -and $AttackerIp -ne "UNKNOWN") {

    # Validación básica de formato IP (anti-injection)
    if ($AttackerIp -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        Write-AirGapLog "ERROR: IP no valida: '$AttackerIp'. Abortando bloqueo por IP."
        exit 1
    }

    $IpRuleName = "${RuleName}_IP_${AttackerIp}"

    # Eliminar regla previa si existe (idempotente)
    netsh advfirewall firewall delete rule name="$IpRuleName" | Out-Null 2>&1

    # Bloquear toda comunicacion desde la IP atacante
    netsh advfirewall firewall add rule `
        name="$IpRuleName" `
        dir=in `
        action=block `
        remoteip="$AttackerIp" `
        enable=yes `
        description="BunkerOS Auto-Air-Gap T1562.004 - Bloqueo IP $AttackerIp"

    Write-AirGapLog "IP $AttackerIp bloqueada en Windows Firewall (regla: $IpRuleName)."
}

# ── Bloqueo de puertos del servidor (defensa en profundidad) ──────────────────
$PortList = $BunkerPorts -join ","

# Eliminar reglas previas por puerto (idempotente)
netsh advfirewall firewall delete rule name="${RuleName}_INBOUND"  | Out-Null 2>&1
netsh advfirewall firewall delete rule name="${RuleName}_OUTBOUND" | Out-Null 2>&1

# Bloquear entrada
netsh advfirewall firewall add rule `
    name="${RuleName}_INBOUND" `
    dir=in `
    action=block `
    protocol=tcp `
    localport="$PortList" `
    enable=yes `
    description="BunkerOS Auto-Air-Gap T1562.004"

# Bloquear salida
netsh advfirewall firewall add rule `
    name="${RuleName}_OUTBOUND" `
    dir=out `
    action=block `
    protocol=tcp `
    localport="$PortList" `
    enable=yes `
    description="BunkerOS Auto-Air-Gap T1562.004"

Write-AirGapLog "Puertos $PortList bloqueados (entrada y salida). Air-Gap activo."
Write-Host "[BUNKER AIR-GAP] Aislamiento de red aplicado correctamente."
exit 0
