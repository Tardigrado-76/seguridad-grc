<#
.SYNOPSIS
    CLARA_Rollback_BAJO.ps1 - Reversión de Cambios de Hardening ENS BAJO
#>
#requires -RunAsAdministrator

Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host " INICIANDO ROLLBACK ENS BAJO: CLARA_Rollback_BAJO.ps1                     " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Yellow

# Restaurar Autorun por defecto
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 145 -Type DWord -ErrorAction SilentlyContinue

Write-Host "`n[OK] Reversión de políticas de ENS Bajo completada." -ForegroundColor Green
