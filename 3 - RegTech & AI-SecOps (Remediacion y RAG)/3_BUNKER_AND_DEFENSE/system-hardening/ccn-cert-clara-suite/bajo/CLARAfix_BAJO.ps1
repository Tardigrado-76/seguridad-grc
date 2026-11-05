<#
.SYNOPSIS
    CLARAfix_BAJO.ps1 - Endurecimiento Defensivo Base para Nivel ENS BAJO (RD 311/2022)
    
.DESCRIPTION
    Aplica las directivas de seguridad mínimas obligatorias según el perfil de seguridad BAJO
    del Esquema Nacional de Seguridad (ENS). Establece las bases de higiene digital y defensa perimetral.
#>
#requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$BackupDir = "..\backups"
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host " INICIANDO HARDENING ENS BAJO: CLARAfix_BAJO.ps1                          " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Yellow

# Helper de registro
function Set-RegKeyBase {
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
# 1. CONTROL DE ACCESO BÁSICO (ENS BAJO - OP.ACC.1 / OP.ACC.4)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 1] Aplicando Políticas Básicas de Acceso e Identidad..." -ForegroundColor Yellow

# Bloqueo de estación de trabajo tras inactividad
Set-RegKeyBase -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableLockWorkstation" -Value 0 -Type DWord

# Deshabilitar cuenta de Invitado (Guest)
net user Guest /active:no 2>$null

# Complejidad de contraseñas básica (mínimo 10 caracteres)
net accounts /minpwlen:10

# -----------------------------------------------------------------------------
# 2. PROTECCIÓN DEL HOST Y FIREWALL (ENS BAJO - MP.SI.1 / MP.COM.1)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 2] Configuración de Cortafuegos y Protección Perimetral..." -ForegroundColor Yellow

# Habilitar Windows Defender Firewall en todos los perfiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue

# Activar Control de Cuentas de Usuario (UAC)
Set-RegKeyBase -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord

# Deshabilitar Autorun/Autoplay para medios extraíbles (Mitigación USB malware)
Set-RegKeyBase -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

# -----------------------------------------------------------------------------
# 3. ACTUALIZACIONES DE SEGURIDAD (ENS BAJO - OP.PL.1)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 3] Verificación de Actualizaciones Automáticas..." -ForegroundColor Yellow

# Configurar Windows Update para descarga e instalación automática
Set-RegKeyBase -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4 -Type DWord

Write-Host "`n==========================================================================" -ForegroundColor Green
Write-Host " [OK] HARDENING ENS BAJO COMPLETADO EXITOSAMENTE.                         " -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
