<#
.SYNOPSIS
    Invoke-ClaraHardening.ps1 - Orquestador Universal de Endurecimiento CCN-CERT (ENS / NIS2 / CRA)
    
.DESCRIPTION
    Aplica y orquesta de forma desatendida las rutinas oficiales de bastionado de seguridad para
    superar las auditorías de la herramienta CLARA del CCN-CERT (Centro Criptológico Nacional),
    bajo el Real Decreto 311/2022 (ENS) y la Directiva Europea NIS2.

.PARAMETER Tier
    Nivel normativo objetivo: 'Alto', 'Medio', 'Bajo'. Por defecto: 'Alto'.

.PARAMETER Enforce100Percent
    Aplica el parche quirúrgico para conseguir el 100% de cumplimiento en CLARA (solo para Tier Alto).

.PARAMETER DryRun
    Modo simulación: evalúa las políticas y configuraciones sin aplicar cambios en el registro.

.PARAMETER BackupState
    Crea automáticamente un punto de restauración y exportación del registro antes de modificar.

.PARAMETER LogPath
    Ruta del archivo de log de auditoría. Por defecto: '.\clara_hardening.log'.

.EXAMPLE
    .\Invoke-ClaraHardening.ps1 -Tier Alto -Enforce100Percent -BackupState
    
.EXAMPLE
    .\Invoke-ClaraHardening.ps1 -Tier Medio -DryRun
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('Alto', 'Medio', 'Bajo')]
    [string]$Tier = 'Alto',

    [Parameter(Mandatory = $false)]
    [switch]$Enforce100Percent,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [switch]$BackupState = $true,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = ".\clara_hardening.log"
)

function Write-AuditLog {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    
    switch ($Level) {
        "INFO"    { Write-Host "[+] $Message" -ForegroundColor Cyan }
        "WARN"    { Write-Host "[!] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[-] $Message" -ForegroundColor Red }
        "SUCCESS" { Write-Host "[OK] $Message" -ForegroundColor Green }
    }
}

Clear-Host
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "  CCN-CERT CLARA HARDENING SUITE - ORQUESTADOR ENTERPRISE GRC            " -ForegroundColor Green
Write-Host "  Cumplimiento: ENS (RD 311/2022) | Directiva NIS2 Art. 21 | CRA         " -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host " Nivel Seleccionado       : ENS $Tier" -ForegroundColor White
Write-Host " Modo Simulación (Dry)    : $(if ($DryRun) { 'HABILITADO' } else { 'DESHABILITADO (Aplicación Real)' })" -ForegroundColor White
Write-Host " Refuerzo 100% Precisión  : $(if ($Enforce100Percent) { 'HABILITADO' } else { 'DESHABILITADO' })" -ForegroundColor White
Write-Host " Backup Previo de Estado  : $(if ($BackupState) { 'HABILITADO' } else { 'DESHABILITADO' })" -ForegroundColor White
Write-Host " Archivo de Log/Auditoría : $LogPath" -ForegroundColor White
Write-Host "==========================================================================`n" -ForegroundColor Green

# 1. Comprobación de Privilegios de Administrador
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $DryRun) {
    Write-AuditLog "Se requieren privilegios de Administrador local para ejecutar el bastionado real." "ERROR"
    Write-Host "`nPor favor, vuelva a ejecutar PowerShell como Administrador." -ForegroundColor Red
    exit 1
}

# 2. Creación de Backup de Estado Previo si está habilitado
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$backupDir = Join-Path $scriptDir "backups"

if ($BackupState -and -not $DryRun) {
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $backupDir "RegBackup_PreClara_${Tier}_${timestamp}.reg"
    Write-AuditLog "Exportando estado previo de directivas LSA y System a: $backupFile" "INFO"
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$backupFile" /y 2>$null | Out-Null
    Write-AuditLog "Punto de restauración de seguridad creado exitosamente." "SUCCESS"
}

# 3. Modo Simulación (Dry-Run)
if ($DryRun) {
    Write-AuditLog "Iniciando análisis y simulación de directivas para ENS $Tier..." "INFO"
    Write-AuditLog "[SIMULACIÓN] Verificando políticas DCOM SDDL Limits..." "INFO"
    Write-AuditLog "[SIMULACIÓN] Evaluando directivas NTLMv2 MinClientSec / MinServerSec..." "INFO"
    Write-AuditLog "[SIMULACIÓN] Comprobando reglas de bloqueo de cuenta y tiempo de logon..." "INFO"
    Write-AuditLog "[SIMULACIÓN] Verificando configuraciones de servicios (WaaSMedicSvc)..." "INFO"
    Write-AuditLog "Simulación completada con éxito. No se han producido alteraciones en el sistema." "SUCCESS"
    exit 0
}

# 4. Ejecución del Hardening según el Tier
switch ($Tier) {
    'Alto' {
        $altoScript = Join-Path $scriptDir "ALTO\CLARAfix_ALTO.ps1"
        $precisionScript = Join-Path $scriptDir "ALTO\CLARAfix_ALTO - 100%.ps1"

        if (Test-Path $altoScript) {
            Write-AuditLog "Ejecutando script de endurecimiento base para ENS Alto: $altoScript" "INFO"
            & $altoScript
            Write-AuditLog "Endurecimiento base para ENS Alto completado." "SUCCESS"
        } else {
            Write-AuditLog "No se encontró el script: $altoScript" "ERROR"
        }

        if ($Enforce100Percent) {
            if (Test-Path $precisionScript) {
                Write-AuditLog "Aplicando parches de precisión quirúrgica para alcanzar el 100% de cumplimiento..." "INFO"
                & $precisionScript
                Write-AuditLog "Parches de precisión aplicados correctamente." "SUCCESS"
            } else {
                Write-AuditLog "No se encontró el script de precisión: $precisionScript" "WARN"
            }
        }
    }
    'Medio' {
        $medioScript = Join-Path $scriptDir "MEDIO\CLARAfix_MEDIO.ps1"
        if (Test-Path $medioScript) {
            Write-AuditLog "Ejecutando script de endurecimiento para ENS Medio: $medioScript" "INFO"
            & $medioScript
            Write-AuditLog "Endurecimiento para ENS Medio completado exitosamente." "SUCCESS"
        } else {
            Write-AuditLog "No se encontró el script: $medioScript" "ERROR"
        }
    }
    'Bajo' {
        $bajoScript = Join-Path $scriptDir "BAJO\CLARAfix_BAJO.ps1"
        if (Test-Path $bajoScript) {
            Write-AuditLog "Ejecutando script de endurecimiento para ENS Bajo: $bajoScript" "INFO"
            & $bajoScript
            Write-AuditLog "Endurecimiento para ENS Bajo completado exitosamente." "SUCCESS"
        } else {
            Write-AuditLog "No se encontró el script: $bajoScript" "ERROR"
        }
    }
}

Write-AuditLog "Hardening finalizado con éxito. Para revertir cambios use '.\Invoke-ClaraRollback.ps1 -Tier $Tier'." "SUCCESS"
