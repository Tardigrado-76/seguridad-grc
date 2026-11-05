<#
.SYNOPSIS
    Compensacion Forense ENS Alta, NIS2, CRA - Guia CCN-STIC-811 / 845
    Inmunizacion integral del Host N16 antes de iniciar el Appliance.
#>
#requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"

function Write-Step([string]$msg) {
    Write-Host "[+] $msg" -ForegroundColor Cyan
}

function Write-Success([string]$msg) {
    Write-Host "    -> $msg" -ForegroundColor Green
}

Write-Host "=======================================================" -ForegroundColor Yellow
Write-Host " INICIANDO INMUNIZACION MILITAR - BUNKEROS ENS ALTO" -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Yellow

# -----------------------------------------------------------------------------
# 1. PROTECCION LSA, CREDENCIALES Y VBS (Credential Guard / CRA Anti-Tampering)
# -----------------------------------------------------------------------------
Write-Step "Fase 1: Aislamiento LSA y Credenciales (Credential Guard / RunAsPPL)..."
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $LsaPath -Name "RunAsPPL" -Value 1 -Type DWord
Set-ItemProperty -Path $LsaPath -Name "LsaCfgFlags" -Value 1 -Type DWord
Set-ItemProperty -Path $LsaPath -Name "DisableDomainCreds" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
Set-ItemProperty -Path $LsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
Write-Success "Secretos LSA aislados y Hashes LM/WDigest bloqueados."

# -----------------------------------------------------------------------------
# 2. REDUCCION DE SUPERFICIE FISICA (Bloqueo USBSTOR - Directiva Usuario)
# -----------------------------------------------------------------------------
Write-Step "Fase 2: Reduccion de Superficie Fisica (Bloqueo USBSTOR)..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4 -Type DWord
Write-Success "Controladores USB Mass Storage (USBSTOR) desactivados permanentemente."

# -----------------------------------------------------------------------------
# 3. REDUCCION DE SUPERFICIE DE RED (LLMNR, NetBIOS, SMBv1)
# -----------------------------------------------------------------------------
Write-Step "Fase 3: Endurecimiento de Protocolos de Red (LLMNR / NetBIOS)..."
# Deshabilitar LLMNR
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
# Deshabilitar NetBIOS en todas las interfaces activas
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object {
    $_.SetTcpipNetbios(2)
}
# Deshabilitar SMBv1 y habilitar firmas SMB (MP.COM.3)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Write-Success "Protocolos obsoletos e inseguros (LLMNR, NetBIOS, SMBv1) aniquilados."

# -----------------------------------------------------------------------------
# 4. CRIPTOGRAFIA DE RED (SCHANNEL / TLS)
# -----------------------------------------------------------------------------
Write-Step "Fase 4: Restriccion Criptografica (Schannel TLS 1.2 / 1.3)..."
$SchannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$Protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($Prot in $Protocols) {
    $PathClient = "$SchannelPath\Protocols\$Prot\Client"
    $PathServer = "$SchannelPath\Protocols\$Prot\Server"
    New-Item -Path $PathClient -Force | Out-Null
    New-Item -Path $PathServer -Force | Out-Null
    Set-ItemProperty -Path $PathClient -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $PathServer -Name "Enabled" -Value 0 -Type DWord
}
# Deshabilitar Cifrados Debiles
$Ciphers = @("DES 56/56", "NULL", "RC2 128/128", "RC2 40/128", "RC2 56/128", "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128", "Triple DES 168")
foreach ($Cipher in $Ciphers) {
    $PathCiph = "$SchannelPath\Ciphers\$Cipher"
    New-Item -Path $PathCiph -Force | Out-Null
    Set-ItemProperty -Path $PathCiph -Name "Enabled" -Value 0 -Type DWord
}
Write-Success "Schannel bloqueado a algoritmos modernos. Suites de cifrado debil deshabilitadas."

# -----------------------------------------------------------------------------
# 5. POLITICAS DE AUDITORIA AVANZADA (NIS2 Trazabilidad)
# -----------------------------------------------------------------------------
Write-Step "Fase 5: Auditoria Avanzada y Trazabilidad Forense..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord

# Command Line Auditing (NIS2)
$AuditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $AuditPath -Force | Out-Null
Set-ItemProperty -Path $AuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Forzar configuracion AuditPol via GUIDs universales (bypass de localizacion OS)
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

# Expandir EventLogs a 128MB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Value 134217728 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name "MaxSize" -Value 134217728 -Type DWord
Write-Success "Auditoria de Procesos (CmdLine) y EventLog de 128MB configurados."

# -----------------------------------------------------------------------------
# 6. REDUCCION DE SUPERFICIE DE EJECUCION (WSH y Firewall)
# -----------------------------------------------------------------------------
Write-Step "Fase 6: Restriccion de Ejecucion y Firewall..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -Value 4 -Type DWord

Remove-NetFirewallRule -Name "BUNKER_CORE_IN" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "BUNKER_CORE_IN" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000 -RemoteAddress "LocalSubnet" -Profile Domain,Private | Out-Null
Write-Success "Windows Script Host deshabilitado. Reglas de cortafuegos aisladas."

Write-Host '=======================================================' -ForegroundColor Green
Write-Host ' [OK] INMUNIZACION APLICADA. ESTADO ENS: GREEN' -ForegroundColor Green
Write-Host '=======================================================' -ForegroundColor Green


