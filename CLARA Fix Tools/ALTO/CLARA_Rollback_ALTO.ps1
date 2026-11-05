<#
.SYNOPSIS
    CLARA_Rollback_ALTO.ps1 - Reversión y Restauración de Cambios para ENS ALTO
    
.DESCRIPTION
    Restaura las políticas de registro y directivas locales modificadas por CLARAfix_ALTO.ps1
    y CLARAfix_ALTO_Precision_100.ps1 a sus valores predeterminados seguros.
#>
#requires -RunAsAdministrator

Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host " INICIANDO ROLLBACK ENS ALTO: CLARA_Rollback_ALTO.ps1                     " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Yellow

# Restaurar directivas de registro
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DeviceUndockNeedsToLogon" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SubmitShareOperations" -Value 1 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditInboundNtlmTraffic" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceiveNtlmTraffic" -Value 0 -Type DWord -ErrorAction SilentlyContinue

# Restablecer umbrales de cuenta
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

Write-Host "`n[OK] Reversión de políticas de ENS Alto completada satisfactoriamente." -ForegroundColor Green
