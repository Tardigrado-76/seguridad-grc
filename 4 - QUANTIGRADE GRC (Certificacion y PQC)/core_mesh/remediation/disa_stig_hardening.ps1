#Requires -RunAsAdministrator
# =============================================================================
# disa_stig_hardening.ps1 - DISA STIG / NATO Baseline Hardening
# =============================================================================

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Applying DISA STIG Host Hardening rules"
Write-Host "===================================================" -ForegroundColor Cyan

# 1. Denegar SeDebugPrivilege
Write-Host "[1/3] Revoking SeDebugPrivilege from non-System users..." -ForegroundColor Yellow
$seceditExport = "$env:TEMP\secpol.cfg"
secedit /export /cfg $seceditExport | Out-Null
$secData = Get-Content $seceditExport

$newSecData = @()
foreach ($line in $secData) {
    if ($line -match "^SeDebugPrivilege") {
        $newSecData += "SeDebugPrivilege = *S-1-5-18" # Local System Only
    } else {
        $newSecData += $line
    }
}
Set-Content -Path $seceditExport -Value $newSecData
secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $seceditExport /areas USER_RIGHTS | Out-Null
Write-Host "[+] SeDebugPrivilege restricted to NT AUTHORITY\SYSTEM" -ForegroundColor Green

# 2. Kernel and Security Auditing
Write-Host "`n[2/3] Configuring strict Kernel and Process Auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable | Out-Null
Write-Host "[+] Auditpol configured successfully" -ForegroundColor Green

# 3. File ACLs on Binaries
Write-Host "`n[3/3] Enforcing ACLs on server binaries..." -ForegroundColor Yellow
$targetExe = Resolve-Path ".\dist\fastapi_server.exe" -ErrorAction SilentlyContinue

if ($targetExe) {
    $acl = Get-Acl $targetExe
    $acl.SetAccessRuleProtection($true, $false)
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $acl.AddAccessRule($systemRule)
    Set-Acl $targetExe $acl
    Write-Host "[+] Strict ACLs applied to $targetExe" -ForegroundColor Green
} else {
    Write-Host "[!] dist\fastapi_server.exe not found. Skipping file-level ACL lock." -ForegroundColor DarkYellow
}

Write-Host "`n===================================================" -ForegroundColor Green
Write-Host "  DISA STIG Hardening applied successfully"
Write-Host "===================================================" -ForegroundColor Green

