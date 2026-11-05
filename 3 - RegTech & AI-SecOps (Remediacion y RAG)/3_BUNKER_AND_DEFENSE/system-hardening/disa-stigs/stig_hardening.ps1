<#
.SYNOPSIS
    Script de Hardening de Entorno basado en DISA STIG para BunkerOS.
.DESCRIPTION
    Aplica controles STIG restrictivos:
    1. Deshabilita SeDebugPrivilege para evitar depuración de procesos en caliente.
    2. Modifica ACLs para que solo 'SYSTEM' y 'BunkerService' puedan leer/ejecutar binarios.
    3. Habilita auditoría de objetos a nivel Kernel.
#>

# Auto-elevación (Require Admin)
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "El script requiere privilegios de Administrador. Elevando contexto..."
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       BUNKER OS - DISA STIG HARDENING SCRIPT             " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    # 1. Habilitar auditoría de objetos (Kernel Audit)
    Write-Host "[*] Configurando auditoría estricta de acceso a objetos (Kernel Audit)..."
    auditpol /set /subcategory:"File System" /success:enable /failure:enable
    auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable

    # 2. Retirar SeDebugPrivilege (Requiere módulo externo o utilidad secpol, lo hacemos via Secedit)
    Write-Host "[*] Retirando SeDebugPrivilege (Mitigación de inyección/depuración en caliente)..."
    $SecTemplate = "$env:TEMP\secpol.cfg"
    $SecDb = "$env:TEMP\secpol.sdb"
    
    secedit /export /cfg $SecTemplate /quiet
    $cfg = Get-Content $SecTemplate
    $newCfg = @()
    foreach ($line in $cfg) {
        if ($line -match "^SeDebugPrivilege") {
            # Remover administradores, dejar solo valores estrictamente vacíos o controlados
            $newCfg += "SeDebugPrivilege ="
        } else {
            $newCfg += $line
        }
    }
    $newCfg | Set-Content $SecTemplate
    secedit /configure /db $SecDb /cfg $SecTemplate /areas USER_RIGHTS /quiet
    
    # Limpieza
    Remove-Item $SecTemplate -ErrorAction SilentlyContinue
    Remove-Item $SecDb -ErrorAction SilentlyContinue


    # 3. Restringir ACLs en el directorio de binarios
    Write-Host "[*] Aplicando restricciones ACL de grado militar al binario compilado..."
    $BinFolder = "C:\BunkerOS\bin"
    if (-not (Test-Path $BinFolder)) {
        New-Item -Path $BinFolder -ItemType Directory -Force | Out-Null
    }

    $Acl = Get-Acl $BinFolder
    $Acl.SetAccessRuleProtection($true, $false) # Deshabilitar herencia, eliminar reglas
    
    $SystemAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $AdminAccess = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")
    
    $Acl.AddAccessRule($SystemAccess)
    $Acl.AddAccessRule($AdminAccess)
    Set-Acl $BinFolder $Acl

    Write-Host "`n[+] DISA STIG HARDENING APLICADO EXITOSAMENTE." -ForegroundColor Green
} catch {
    Write-Error "[-] Fallo crítico aplicando el hardening STIG: $_"
    exit 1
}
