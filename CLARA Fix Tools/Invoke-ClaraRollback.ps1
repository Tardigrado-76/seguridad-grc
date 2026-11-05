<#
.SYNOPSIS
    Invoke-ClaraRollback.ps1 - Orquestador Universal de Reversion de Hardening CCN-CERT
    
.DESCRIPTION
    Permite revertir de forma segura las directivas de registro y configuraciones de seguridad
    aplicadas por la suite CLARA FIX TOOLS.

.PARAMETER Tier
    Nivel normativo a revertir: 'Alto', 'Medio', 'Bajo'. Por defecto: 'Alto'.

.PARAMETER RestoreBackupFile
    Ruta a un archivo .reg de backup especifico para restaurar el estado previo del registro.

.EXAMPLE
    .\Invoke-ClaraRollback.ps1 -Tier Alto
    
.EXAMPLE
    .\Invoke-ClaraRollback.ps1 -RestoreBackupFile ".\backups\RegBackup_PreClara_Alto_20260818.reg"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('Alto', 'Medio', 'Bajo')]
    [string]$Tier = 'Alto',

    [Parameter(Mandatory = $false)]
    [string]$RestoreBackupFile
)

Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host "  CCN-CERT CLARA SUITE - ORQUESTADOR DE ROLLBACK Y RESTAURACION           " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Yellow

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[-] ERROR: Se requieren privilegios de Administrador para ejecutar el rollback del sistema." -ForegroundColor Red
    exit 1
}

if ($RestoreBackupFile) {
    if (Test-Path $RestoreBackupFile) {
        Write-Host "[+] Restaurando copia de seguridad de registro desde: $RestoreBackupFile" -ForegroundColor Cyan
        reg import "$RestoreBackupFile"
        Write-Host "[OK] Registro restaurado satisfactoriamente desde archivo de respaldo." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "[-] ERROR: No se encontro el archivo de respaldo: $RestoreBackupFile" -ForegroundColor Red
        exit 1
    }
}

switch ($Tier) {
    'Alto' {
        $rollbackScript = Join-Path $scriptDir "ALTO\CLARA_Rollback_ALTO.ps1"
        if (Test-Path $rollbackScript) {
            & $rollbackScript
        } else {
            Write-Host "[-] No se encontro el script: $rollbackScript" -ForegroundColor Red
        }
    }
    'Medio' {
        $rollbackScript = Join-Path $scriptDir "MEDIO\CLARA_Rollback_MEDIO.ps1"
        if (Test-Path $rollbackScript) {
            & $rollbackScript
        } else {
            Write-Host "[-] No se encontro el script: $rollbackScript" -ForegroundColor Red
        }
    }
    'Bajo' {
        $rollbackScript = Join-Path $scriptDir "BAJO\CLARA_Rollback_BAJO.ps1"
        if (Test-Path $rollbackScript) {
            & $rollbackScript
        } else {
            Write-Host "[-] No se encontro el script: $rollbackScript" -ForegroundColor Red
        }
    }
}

Write-Host "[OK] Procedimiento de rollback para ENS $Tier finalizado." -ForegroundColor Green
