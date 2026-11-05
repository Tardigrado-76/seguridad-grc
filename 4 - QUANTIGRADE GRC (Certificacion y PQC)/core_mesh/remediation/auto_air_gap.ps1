<#
.SYNOPSIS
    BunkerOS & Quantigrade GCR Auto-Air-Gap Script (PowerShell / Windows)
    MITRE ATT&CK: T1562.004 - Impair Defenses: Disable or Modify System Firewall

.PARAMETER MitreId
    MITRE ATT&CK identifier that triggered the air-gap isolation.

.PARAMETER AttackerIp
    Target attacker IP address to block.

.PARAMETER DryRun
    Simulates isolation without modifying Windows Firewall rules.
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$MitreId = "UNKNOWN",

    [Parameter(Mandatory=$false)]
    [string]$AttackerIp = "",

    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Timestamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir      = Join-Path $ScriptDir "..\..\reports"
$LogFile     = Join-Path $LogDir "air_gap_activations.log"
$BunkerPorts = @(8000, 8010, 8443)
$RuleName    = "QUANTIGRADE_AIR_GAP"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-AirGapLog {
    param([string]$Message)
    $Entry = "[$Timestamp] $Message"
    Add-Content -Path $LogFile -Value $Entry -Encoding UTF8
    Write-Host "[QUANTIGRADE AIR-GAP] $Message"
}

Write-AirGapLog "T1562.004 - Air-Gap trigger. MITRE: $MitreId | Attacker: $AttackerIp | DryRun: $($DryRun.IsPresent)"

if ($DryRun.IsPresent) {
    Write-AirGapLog "[DRY-RUN] Simulated air-gap isolation. No firewall mutations applied."
    exit 0
}

# Block Attacker IP if specified
if ($AttackerIp -ne "" -and $AttackerIp -ne "UNKNOWN") {
    if ($AttackerIp -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        Write-AirGapLog "ERROR: Invalid IP format: '$AttackerIp'. Aborting IP block."
        exit 1
    }

    $IpRuleName = "${RuleName}_IP_${AttackerIp}"
    netsh advfirewall firewall delete rule name="$IpRuleName" | Out-Null 2>&1
    netsh advfirewall firewall add rule `
        name="$IpRuleName" `
        dir=in `
        action=block `
        remoteip="$AttackerIp" `
        enable=yes `
        description="Quantigrade Auto-Air-Gap T1562.004 - Block IP $AttackerIp"

    Write-AirGapLog "IP $AttackerIp blocked in Windows Firewall ($IpRuleName)."
}

# Block exposed service ports
$PortList = $BunkerPorts -join ","
netsh advfirewall firewall delete rule name="${RuleName}_INBOUND"  | Out-Null 2>&1
netsh advfirewall firewall delete rule name="${RuleName}_OUTBOUND" | Out-Null 2>&1

netsh advfirewall firewall add rule `
    name="${RuleName}_INBOUND" `
    dir=in `
    action=block `
    protocol=tcp `
    localport="$PortList" `
    enable=yes `
    description="Quantigrade Auto-Air-Gap T1562.004"

netsh advfirewall firewall add rule `
    name="${RuleName}_OUTBOUND" `
    dir=out `
    action=block `
    protocol=tcp `
    localport="$PortList" `
    enable=yes `
    description="Quantigrade Auto-Air-Gap T1562.004"

Write-AirGapLog "Ports $PortList blocked (inbound & outbound). Host Air-Gap active."
exit 0

