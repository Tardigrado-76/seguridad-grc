<#
.SYNOPSIS
    CLARA_Rollback_MEDIO.ps1 - Reversión de Cambios de Hardening ENS MEDIO
    
.DESCRIPTION
    Restaura los valores por defecto del sistema para las directivas aplicadas por CLARAfix_MEDIO.ps1.
#>
#requires -RunAsAdministrator

Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host " INICIANDO ROLLBACK ENS MEDIO: CLARA_Rollback_MEDIO.ps1                   " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Yellow

# Restaurar valores por defecto de Windows
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 3 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord -ErrorAction SilentlyContinue

# Restablecer umbrales de cuenta
net accounts /lockoutthreshold:0

Write-Host "`n[OK] Reversión de políticas de ENS Medio completada." -ForegroundColor Green
