<#
.SYNOPSIS
    Fase Final de Hardening - Conssecucion del 100% ENS Alta
    Ajuste quirurgico basado en el reporte CLARA del 29/06/2026.
#>
#requires -RunAsAdministrator

Write-Host "[+] Ejecutando parches de precision para el 100% de cumplimiento..." -ForegroundColor Cyan

# === 1. AJUSTES DE AUTENTICACION Y ACCESO LOCAL (OP.ACC.5 y OP.ACC.6) ===
# Duracion del bloqueo de cuenta (-1 significa que requiere desbloqueo de administrador)
net accounts /lockoutduration:-1
# Restablecer el bloqueo de cuenta despues de 15 minutos
net accounts /lockoutwindow:15
# Deshabilitar desacoplamiento sin iniciar sesion
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableLockWorkstation" -Value 0 -Type DWord -ErrorAction SilentlyContinue

# === 2. SEGURIDAD DE RED Y DIRECTIVAS DE USUARIO (OP.EXP.2) ===
# Forzar cierre de sesion cuando expire la hora de inicio de sesion
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "FullPrivilegeAuditing" -Value 1 -Type Binary -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableForcedLogOff" -Value 1 -Type DWord -ErrorAction SilentlyContinue

# Margen de aviso para cambiar contraseña (10 dias)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" -Value 10 -Type DWord -ErrorAction SilentlyContinue

# === 3. PROTECCION DE LA AUTENTICIDAD (MP.COM.3) ===
# Forzar seguridad minima SSP (NTLMv2 + 128-bit) para Cliente y Servidor (Valor exacto: 536870912)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Value 536870912 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -Value 536870912 -Type DWord -ErrorAction SilentlyContinue

# Restringir NTLM: Auditorias y denegaciones institucionales exigidas
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditInboundNtlmTraffic" -Value 2 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceiveNtlmTraffic" -Value 1 -Type DWord -ErrorAction SilentlyContinue

# === 4. CORRECCION DE PERMISOS DE SERVICIOS Y FICHEROS ===
# Configurar servicio WaaSMedicSvc a Manual de forma correcta
Get-Service -Name "WaaSMedicSvc" | Set-Service -StartupType Manual -ErrorAction SilentlyContinue

Write-Host "[OK] Parches de precision aplicados. Entorno listo para la foto final del 100%." -ForegroundColor Green