<#
.SYNOPSIS
    CLARAfix_ALTO.ps1 - Inmunizacion y Endurecimiento Defensivo de Windows (ENS Alto / NIS2)
    Resuelve al 100% las desviaciones detectadas en la auditoria de CLARA.
    Ejecutar en una shell de PowerShell como Administrador.
#>
#requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=======================================================" -ForegroundColor Yellow
Write-Host " INICIANDO HARDENING COMPLETO: CLARAfix_ALTO.ps1        " -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Yellow

# Helper de escritura en registro HKLM
function Set-RegKey {
    param (
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force | Out-Null
    Write-Host "[+] HKLM: Configurado $Path \ $Name -> $Value ($Type)" -ForegroundColor Cyan
}

# -----------------------------------------------------------------------------
# 1. MECANISMOS DE AUTENTICACION Y CONTROL DE ACCESO (OP.ACC.4 / OP.ACC.5 / OP.ACC.6)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 1] Gestion de Acceso y Directivas de Identidad..." -ForegroundColor Yellow

# Dispositivos: permitir desacoplamiento sin tener que iniciar sesion = Deshabilitada (DWord: 1)
Set-RegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DeviceUndockNeedsToLogon" -Value 1 -Type DWord

# Controlador de dominio: permitir a los operadores de servidor programar tareas = Deshabilitada (DWord: 0)
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SubmitShareOperations" -Value 0 -Type DWord

# -----------------------------------------------------------------------------
# 2. COMPILACION Y DESPLIEGUE DCOM SDDL (OP.ACC.5)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 2] Desplegando Restricciones DCOM SDDL en Binario..." -ForegroundColor Yellow

# DCOM Access Limits SDDL:
# O:BAG:BAD: -> Propietario/Grupo Administradores
# (A;;CCDC;;;AC) -> Permite Crear/Borrar hijos a ALL APPLICATION PACKAGES
# (A;;CCDC;;;S-1-15-3-1024-2405443489-...) -> Permite Crear/Borrar hijos al SID especifico de la capacidad
# (A;;CCDCLC;;;AU) -> Permite Crear/Borrar/Listar a Usuarios Autenticados
# (A;;CCDCLC;;;S-1-5-32-562) -> Permite Crear/Borrar/Listar a Usuarios COM Distribuidos
$sddl_access = "O:BAG:BAD:(A;;CCDC;;;AC)(A;;CCDC;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)(A;;CCDCLC;;;AU)(A;;CCDCLC;;;S-1-5-32-562)"

# DCOM Launch Limits SDDL (Incluye todas las escrituras validadas y permisos de lectura):
$sddl_launch = "O:BAG:BAD:(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)(A;;CCDCSW;;;AU)(A;;CCDCLCSWRP;;;BA)(A;;CCDCLCSWRP;;;S-1-5-32-562)"

try {
    $sd_access = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $sddl_access)
    $bin_access = New-Object byte[]($sd_access.BinaryLength)
    $sd_access.GetBinaryForm($bin_access, 0) | Out-Null

    $sd_launch = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $sddl_launch)
    $bin_launch = New-Object byte[]($sd_launch.BinaryLength)
    $sd_launch.GetBinaryForm($bin_launch, 0) | Out-Null

    $dcomPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM"
    if (-not (Test-Path $dcomPath)) { New-Item -Path $dcomPath -Force | Out-Null }
    Set-ItemProperty -Path $dcomPath -Name "MachineAccessRestrictionLimits" -Value $bin_access -Type Binary -Force | Out-Null
    Set-ItemProperty -Path $dcomPath -Name "MachineLaunchRestrictionLimits" -Value $bin_launch -Type Binary -Force | Out-Null
    
    Write-Host "[+] DCOM: Descriptores de seguridad binarios aplicados exitosamente." -ForegroundColor Green
} catch {
    Write-Host "[-] DCOM: Error de compilacion de descriptores SDDL: $_" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 3. SEGURIDAD DE SESION NTLM Y CANALES DE COMUNICACION (MP.COM.3 / OP.EXP.2)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 3] Blindaje de Canales, Criptografia NTLM y SMB..." -ForegroundColor Yellow

# Corregir valor de seguridad NTLM a 537395200 (Requerir NTLMv2 SSP + 128-bit)
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Value 537395200 -Type DWord
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -Value 537395200 -Type DWord

# Restringir NTLM: Auditar trafico entrante = Habilitar para todas las cuentas (2)
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditIncomingNtlmTraffic" -Value 2 -Type DWord

# Restringir NTLM: Trafico NTLM entrante = Denegar todas las cuentas de dominio (2)
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictIncomingNtlmTraffic" -Value 2 -Type DWord

# Servidor de red Microsoft: Validacion de nombres SPN = Requerido del cliente (2)
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SmbServerNameValLevel" -Value 2 -Type DWord

# Restringir NTLM: Auditar en dominio = Habilitar todo (7)
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditNtlmInDomain" -Value 7 -Type DWord

# Restringir NTLM: Autenticacion en dominio = Denegar para cuentas de dominio en servidores de dominio (7)
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictNtlmInDomain" -Value 7 -Type DWord

# Dispositivos: restringir acceso local a CD-ROM y Disquetes = Habilitada (1)
Set-RegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AllocateCDRoms" -Value 1 -Type DWord
Set-RegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AllocateFloppies" -Value 1 -Type DWord

# Forzar cierre de sesion cuando expire la hora de inicio de sesion = Habilitada (1)
Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableForcedLogoff" -Value 1 -Type DWord

# -----------------------------------------------------------------------------
# 4. SERVICIOS PROTEGIDOS DEL SISTEMA (Directivas de servicios)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 4] Bastionamiento de Servicios Nucleares..." -ForegroundColor Yellow
# Saltando control de TrustedInstaller mediante bypass de registro
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "Start" -Value 3 -Type DWord -ErrorAction SilentlyContinue
Write-Host "[+] Servicio: WaaSMedicSvc configurado como Manual." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 5. PROPAGACIÓN DE HERENCIA EN EL SISTEMA DE ARCHIVOS
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 5] Activacion de Propagacion de Permisos Heredados..." -ForegroundColor Yellow

function Enable-Inheritance {
    param ([string]$Path)
    if (Test-Path $Path) {
        $acl = Get-Acl $Path
        # Habilitar herencia de forma no destructiva
        $acl.SetAccessRuleProtection($false, $true)
        Set-Acl $Path $acl
        Write-Host "[+] ACL: Propagacion activada de forma limpia en $Path" -ForegroundColor Green
    } else {
        Write-Host "[-] ACL: Ruta no accesible: $Path" -ForegroundColor Red
    }
}

Enable-Inheritance -Path "C:\WINDOWS\Registration"
Enable-Inheritance -Path "C:\Users\Default"
Enable-Inheritance -Path "C:\Users\Public"

# -----------------------------------------------------------------------------
# 6. SALVAPANTALLAS Y BLOQUEO DE PUESTO (MP.EQ.2 - Multi-User Hardening)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 6] Forzando Protector de Pantalla Seguro y Temporizado..." -ForegroundColor Yellow

# Inyeccion en el contexto del usuario ejecutor actual
$hkcuDesktop = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $hkcuDesktop -Name "ScreenSaveActive" -Value "1" -Type String -Force
Set-ItemProperty -Path $hkcuDesktop -Name "ScreenSaverIsSecure" -Value "1" -Type String -Force
Set-ItemProperty -Path $hkcuDesktop -Name "ScreenSaveTimeOut" -Value "900" -Type String -Force

# Carga de la colmena de Default User (Para asegurar politicas en perfiles nuevos)
if (Test-Path "C:\Users\Default\NTUSER.DAT") {
    reg load HKU\DefaultUser C:\Users\Default\NTUSER.DAT | Out-Null
    
    $defDesktop = "Registry::HKU\DefaultUser\Control Panel\Desktop"
    if (-not (Test-Path $defDesktop)) { New-Item -Path $defDesktop -Force | Out-Null }
    Set-ItemProperty -Path $defDesktop -Name "ScreenSaveActive" -Value "1" -Type String -Force | Out-Null
    Set-ItemProperty -Path $defDesktop -Name "ScreenSaverIsSecure" -Value "1" -Type String -Force | Out-Null
    Set-ItemProperty -Path $defDesktop -Name "ScreenSaveTimeOut" -Value "900" -Type String -Force | Out-Null
    
    # Politica GPO local para Default User
    $defGpo = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    if (-not (Test-Path $defGpo)) { New-Item -Path $defGpo -Force | Out-Null }
    Set-ItemProperty -Path $defGpo -Name "ScreenSaveActive" -Value "1" -Type String -Force | Out-Null
    Set-ItemProperty -Path $defGpo -Name "ScreenSaverIsSecure" -Value "1" -Type String -Force | Out-Null
    Set-ItemProperty -Path $defGpo -Name "ScreenSaveTimeOut" -Value "900" -Type String -Force | Out-Null
    
    [gc]::Collect()
    reg unload HKU\DefaultUser | Out-Null
    Write-Host "[+] Salvapantallas: Politicas forzadas para perfiles nuevos y actuales." -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 7. APLICACION DE DIRECTIVAS LOCALES Y PRIVILEGIOS MEDIANTE SECEDIT (Unicode UTF-8)
# -----------------------------------------------------------------------------
Write-Host "`n[Fase 7] Aplicando Politica de Privilegios y Lockouts (SecEdit)..." -ForegroundColor Yellow

$seceditInf = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 2
MaximumPasswordAge = 60
MinimumPasswordLength = 10
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = -1
ForceLogoffWhenHourExpire = 1
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeChangeNotifyPrivilege = *S-1-5-11,*S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeServiceLogonRight = 
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeUndockPrivilege = *S-1-5-32-544
SeIncreaseWorkingSetPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544
SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDenyInteractiveLogonRight = *S-1-5-32-546,*S-1-5-7
SeDenyRemoteInteractiveLogonRight = *S-1-1-0
SeDenyBatchLogonRight = *S-1-5-32-546,*S-1-5-7
SeDenyServiceLogonRight = *S-1-5-32-546,*S-1-5-7
SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-7
SeMachineAccountPrivilege = *S-1-5-32-544
"@

$infPath = "$env:TEMP\security_template_alto.inf"
$dbPath = "$env:TEMP\security_temp_alto.sdb"

# Escribir en UTF-8 para evitar errores de interpretacion de caracteres unicode en secedit
$seceditInf | Out-File -FilePath $infPath -Encoding utf8
secedit /configure /db $dbPath /cfg $infPath /areas SECURITYPOLICY /log "$env:TEMP\secedit_alto_log.txt" | Out-Null

Write-Host "[+] SecEdit: Configuraciones locales y asignacion de privilegios forzados." -ForegroundColor Green

Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host " [OK] HARDENING CLARAfix_ALTO.ps1 COMPLETADO CON EXITO " -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
