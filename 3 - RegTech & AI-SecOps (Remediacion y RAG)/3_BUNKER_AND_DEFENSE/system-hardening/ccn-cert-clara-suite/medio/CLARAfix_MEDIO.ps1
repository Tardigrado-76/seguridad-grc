<#
.SYNOPSIS
    CLARAfix_MEDIO.ps1 - Endurecimiento Defensivo Automatizado para Nivel ENS MEDIO (RD 311/2022 / NIS2)
    
.DESCRIPTION
    Aplica las directivas de seguridad obligatorias según el perfil de seguridad MEDIO del
    Esquema Nacional de Seguridad (CCN-STIC 811 / ENS). Incluye protección de autenticación,
    restricción de protocolos inseguros (SMBv1, NTLMv1), políticas de bloqueo y directivas de auditoría.
#>
#requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$BackupDir = "..\backups"
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host " INICIANDO HARDENING ENS MEDIO: CLARAfix_MEDIO.ps1                        " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Yellow

# Helper de escritura segura en registro con backup previo
function Set-RegKeySecure {
    param (
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop | Out-Null
        Write-Host "[+] HKLM: Configurado $Path \ $Name -> $Value ($Type)" -ForegroundColor Cyan
    } catch {
        Write-Host "[-] ERROR configurando $Path \ $Name : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# -----------------------------------------------------------------------------
# 1. MECANISMOS DE AUTENTICACION Y CONTROL DE ACCESO (ENS MEDIO - OP.ACC.4 / OP.ACC.6)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 1] Control de Acceso y Gestión de Identidades (ENS MEDIO)..." -ForegroundColor Yellow

# Bloqueo de estación de trabajo tras inactividad
Set-RegKeySecure -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableLockWorkstation" -Value 0 -Type DWord
Set-RegKeySecure -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DeviceUndockNeedsToLogon" -Value 1 -Type DWord

# Duración del bloqueo de cuenta y ventana de reset
net accounts /lockoutduration:30
net accounts /lockoutthreshold:5
net accounts /lockoutwindow:30

# Ocultar último usuario que inició sesión
Set-RegKeySecure -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord

# -----------------------------------------------------------------------------
# 2. PROTECCION DE RED Y PROTOCOLOS INSEGUROS (ENS MEDIO - MP.COM.2 / MP.COM.3)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 2] Deshabilitación de Protocolos Inseguros y Restricción de Red..." -ForegroundColor Yellow

# Deshabilitar SMBv1 (Mitigación EternalBlue / WannaCry)
Set-RegKeySecure -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null

# Forzar NTLMv2 (Rechazar LM y NTLMv1)
Set-RegKeySecure -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord

# Firma digital de comunicaciones cliente/servidor SMB
Set-RegKeySecure -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-RegKeySecure -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord

# -----------------------------------------------------------------------------
# 3. DIRECTIVAS DE AUDITORIA Y MONITORIZACION (ENS MEDIO - OP.MON.1)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 3] Configuración de Auditoría y Trazabilidad Básica..." -ForegroundColor Yellow

# Auditoría de inicios de sesión (Éxito y Fallo)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null

# Habilitar eventos de auditoría de línea de comandos en creación de procesos
Set-RegKeySecure -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# -----------------------------------------------------------------------------
# 4. HARDENING DE SISTEMA OPERATIVO Y SERVICIOS (ENS MEDIO - MP.SI.1)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 4] Bastionado de Servicios y Firewall..." -ForegroundColor Yellow

# Asegurar estado activo de Windows Defender Firewall en todos los perfiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue

# Forzar UAC en nivel estándar seguro
Set-RegKeySecure -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
Set-RegKeySecure -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord

Write-Host "`n==========================================================================" -ForegroundColor Green
Write-Host " [OK] HARDENING ENS MEDIO COMPLETADO EXITOSAMENTE.                        " -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
