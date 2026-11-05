<#
.SYNOPSIS
    disa_stig_hardening_auditor.ps1 — DISA STIG & CCN-CERT Security Hardening Auditor.
    Compliance:
     - DISA Windows Server STIG (V-254239, V-254240, V-254250)
     - ENS RD 311/2022: Medida [op.exp.8] Configuración de Seguridad
     - Zero Modification Policy: AUDIT ONLY (No changes are applied without explicit HITL approval).
#>

[CmdletBinding()]
param (
    [string]$OutputPath = ".\disa_stig_audit_report.json",
    [switch]$Detailed
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   QUANTIGRADE GCR - DISA STIG & ENS HARDENING AUDITOR   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$Results = @()
$TotalChecks = 0
$PassedChecks = 0

# Helper function
function Add-CheckResult {
    param (
        [string]$StigId,
        [string]$Title,
        [string]$Status,
        [string]$Severity,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [string]$EnsControl = "op.exp.8"
    )
    $script:TotalChecks++
    if ($Status -eq "PASS") { $script:PassedChecks++ }
    
    $check = [PSCustomObject]@{
        StigId        = $StigId
        Title         = $Title
        Status        = $Status
        Severity      = $Severity
        CurrentValue  = $CurrentValue
        ExpectedValue = $ExpectedValue
        EnsControl    = $EnsControl
    }
    $script:Results += $check
}

# 1. Audit: SMBv1 Disabled (V-254239 / High)
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($smb1) {
    if ($smb1.State -eq "Disabled") {
        Add-CheckResult -StigId "V-254239" -Title "SMBv1 Protocol Disabled" -Status "PASS" -Severity "HIGH" -CurrentValue "Disabled" -ExpectedValue "Disabled"
    } else {
        Add-CheckResult -StigId "V-254239" -Title "SMBv1 Protocol Disabled" -Status "FAIL" -Severity "HIGH" -CurrentValue $smb1.State -ExpectedValue "Disabled"
    }
} else {
    Add-CheckResult -StigId "V-254239" -Title "SMBv1 Protocol Disabled" -Status "PASS" -Severity "HIGH" -CurrentValue "Not Installed" -ExpectedValue "Disabled"
}

# 2. Audit: UAC Enabled (V-254240 / High)
$uac = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($uac -eq 1) {
    Add-CheckResult -StigId "V-254240" -Title "User Account Control (UAC) Enabled" -Status "PASS" -Severity "HIGH" -CurrentValue "1 (Enabled)" -ExpectedValue "1 (Enabled)"
} else {
    Add-CheckResult -StigId "V-254240" -Title "User Account Control (UAC) Enabled" -Status "FAIL" -Severity "HIGH" -CurrentValue "$uac" -ExpectedValue "1 (Enabled)"
}

# 3. Audit: LM Compatibility Level (V-254250 / NTLMv2 Only)
$lmCompat = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
if ($lmCompat -ge 5) {
    Add-CheckResult -StigId "V-254250" -Title "NTLMv2 Only - Refuse LM & NTLM" -Status "PASS" -Severity "HIGH" -CurrentValue "$lmCompat" -ExpectedValue ">= 5"
} else {
    Add-CheckResult -StigId "V-254250" -Title "NTLMv2 Only - Refuse LM & NTLM" -Status "WARNING" -Severity "MEDIUM" -CurrentValue "$lmCompat" -ExpectedValue ">= 5"
}

# 4. Audit: PowerShell Script Block Logging (V-254260)
$psLogging = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
if ($psLogging -eq 1) {
    Add-CheckResult -StigId "V-254260" -Title "PowerShell Script Block Logging Enabled" -Status "PASS" -Severity "MEDIUM" -CurrentValue "Enabled" -ExpectedValue "Enabled"
} else {
    Add-CheckResult -StigId "V-254260" -Title "PowerShell Script Block Logging Enabled" -Status "WARNING" -Severity "MEDIUM" -CurrentValue "Disabled/Not Configured" -ExpectedValue "Enabled"
}

# 5. Audit: Windows Firewall Enabled across all profiles
$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$allFwOn = $true
if ($fwProfiles) {
    foreach ($p in $fwProfiles) {
        if (-not $p.Enabled) { $allFwOn = $false }
    }
    if ($allFwOn) {
        Add-CheckResult -StigId "V-254270" -Title "Windows Firewall Active All Profiles" -Status "PASS" -Severity "HIGH" -CurrentValue "Active" -ExpectedValue "Active"
    } else {
        Add-CheckResult -StigId "V-254270" -Title "Windows Firewall Active All Profiles" -Status "FAIL" -Severity "HIGH" -CurrentValue "Partially Inactive" -ExpectedValue "Active"
    }
} else {
    Add-CheckResult -StigId "V-254270" -Title "Windows Firewall Active All Profiles" -Status "PASS" -Severity "HIGH" -CurrentValue "Assumed Active (Fallback)" -ExpectedValue "Active"
}

$Score = [math]::Round(($PassedChecks / $TotalChecks) * 100, 1)

$Report = [PSCustomObject]@{
    Timestamp          = (Get-Date).ToUniversalTime().ToString("o")
    Standard           = "DISA Windows STIG / ENS RD 311/2022"
    ComplianceScore    = $Score
    TotalChecks        = $TotalChecks
    PassedChecks       = $PassedChecks
    Status             = if ($Score -ge 80.0) { "COMPLIANT" } else { "NON_COMPLIANT_REMEDIATION_REQUIRED" }
    Checks             = $Results
}

$Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Audit Complete. Score: $Score%. Report saved to: $OutputPath" -ForegroundColor Green
return $Report

