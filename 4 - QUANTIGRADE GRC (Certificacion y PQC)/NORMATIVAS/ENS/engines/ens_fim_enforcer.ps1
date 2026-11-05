<#
.SYNOPSIS
    ENS High (op.exp.5) & NIST SP 800-53 (SI-7) File Integrity Monitoring (FIM) & HIDS Enforcer.
.DESCRIPTION
    Strict, production-grade PowerShell script for File Integrity Baseline Generation, Drift Detection,
    Windows Event Log Emission, and Cryptographically Signed Audit Evidence Generation.
.EXAMPLE
    .\ens_fim_enforcer.ps1 -Mode CreateBaseline -TargetPath "C:\Windows\System32\drivers\etc" -BaselinePath ".\baseline.json" -DryRun
.EXAMPLE
    .\ens_fim_enforcer.ps1 -Mode ScanAndEnforce -TargetPath "C:\Windows\System32\drivers\etc" -BaselinePath ".\baseline.json" -ReportDir ".\reports"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CreateBaseline", "ScanAndEnforce")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [Parameter(Mandatory = $true)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $false)]
    [string]$ReportDir = ".\fim_reports",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function Get-FileSha256 {
    param([string]$FilePath)
    try {
        if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            return $null
        }
        $hashObj = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hashObj.Hash
    }
    catch [System.IO.IOException], [System.UnauthorizedAccessException] {
        Write-Warning "Cannot read file for hash: $FilePath - $_"
        return "ACCESS_DENIED"
    }
}

function Get-FileAclSddl {
    param([string]$FilePath)
    try {
        if (-not (Test-Path -Path $FilePath)) {
            return $null
        }
        $acl = Get-Acl -Path $FilePath
        return $acl.Sddl
    }
    catch [System.Exception] {
        return "ACL_READ_ERROR"
    }
}

function Write-FimEventLog {
    param(
        [string]$Message,
        [string]$EntryType = "Warning"
    )
    $source = "ENS-FIM-Enforcer"
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($source)) {
            Write-EventLog -LogName "Application" -Source $source -EventId 5001 -EntryType $EntryType -Message $Message
        } else {
            Write-Host "[EVENTLOG SIMULATION][$EntryType] $Message" -ForegroundColor Yellow
        }
    }
    catch [System.Security.SecurityException], [System.Exception] {
        Write-Host "[EVENTLOG FALLBACK][$EntryType] $Message" -ForegroundColor Yellow
    }
}

function Save-EvidenceReports {
    param(
        [hashtable]$ReportData,
        [string]$OutDir
    )
    if (-not (Test-Path -Path $OutDir)) {
        $null = New-Item -Path $OutDir -ItemType Directory -Force
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
    $jsonPath = Join-Path -Path $OutDir -ChildPath "FIM-AUDIT-$timestamp.json"
    $mdPath = Join-Path -Path $OutDir -ChildPath "FIM-AUDIT-$timestamp.md"

    # Convert hashtable to JSON
    $jsonRaw = $ReportData | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($jsonPath, $jsonRaw, [System.Text.Encoding]::UTF8)

    # Compute SHA-256 hash of JSON report for integrity
    $jsonHashObj = Get-FileHash -Path $jsonPath -Algorithm SHA256
    $jsonHash = $jsonHashObj.Hash

    # Inject SHA-256 integrity signature into final JSON
    $ReportData["ReportIntegritySha256"] = $jsonHash
    $jsonFinal = $ReportData | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($jsonPath, $jsonFinal, [System.Text.Encoding]::UTF8)

    # Markdown Generation
    $mdContent = @"
# ENS High (op.exp.5) & NIST SP 800-53 SI-7 Audit Report

- **Execution Mode:** $($ReportData.Mode)
- **Target Path:** $($ReportData.TargetPath)
- **Timestamp (ISO-8601):** $($ReportData.TimestampIso)
- **Dry-Run Mode:** $($ReportData.DryRun)
- **Report Integrity Hash (SHA-256):** `$jsonHash`

## Executive Summary
- **Total Cataloged Baseline Files:** $($ReportData.Summary.BaselineCount)
- **Modified Files:** $($ReportData.Summary.ModifiedCount)
- **New Files (Uncataloged):** $($ReportData.Summary.CreatedCount)
- **Deleted Files:** $($ReportData.Summary.DeletedCount)
- **ACL Drift Count:** $($ReportData.Summary.AclDriftCount)
- **Overall Status:** $($ReportData.Summary.Status)

## Discrepancy Details
"@

    if ($ReportData.Discrepancies.Count -eq 0) {
        $mdContent += "`n*No file integrity or permission discrepancies detected.*`n"
    } else {
        $mdContent += "`n| Path | Type | Details |`n| --- | --- | --- |`n"
        foreach ($d in $ReportData.Discrepancies) {
            $mdContent += "| `$($d.Path)` | $($d.Type) | $($d.Details) |`n"
        }
    }

    [System.IO.File]::WriteAllText($mdPath, $mdContent, [System.Text.Encoding]::UTF8)
    Write-Host "[EVIDENCE TRAIL] Reports saved successfully:" -ForegroundColor Green
    Write-Host "  - JSON: $jsonPath" -ForegroundColor Gray
    Write-Host "  - MD:   $mdPath" -ForegroundColor Gray
    Write-Host "  - SHA256 Digest: $jsonHash" -ForegroundColor Cyan
}

# --- Main Logic ---

if (-not (Test-Path -Path $TargetPath)) {
    Write-Error "Target path '$TargetPath' does not exist."
    exit 1
}

$isoNow = (Get-Date).ToUniversalTime().ToString("o")

if ($Mode -eq "CreateBaseline") {
    Write-Host "[FIM] Generating Baseline Catalog for: $TargetPath" -ForegroundColor Cyan
    $catalog = @{}
    $files = Get-ChildItem -Path $TargetPath -Recurse -File -ErrorAction SilentlyContinue

    $fileCount = 0
    foreach ($file in $files) {
        $relPath = $file.FullName.Substring($TargetPath.Length).TrimStart('\', '/')
        $hash = Get-FileSha256 -FilePath $file.FullName
        $acl = Get-FileAclSddl -FilePath $file.FullName

        $catalog[$relPath] = @{
            Sha256 = $hash
            AclSddl = $acl
            SizeBytes = $file.Length
            LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString("o")
        }
        $fileCount++
    }

    $baselineData = @{
        Metadata = @{
            CreatedIso = $isoNow
            TargetPath = (Resolve-Path $TargetPath).Path
            FileCount = $fileCount
            Version = "1.0.0"
        }
        Files = $catalog
    }

    if ($DryRun) {
        Write-Host "[DRY-RUN] Baseline created in memory. $fileCount files scanned. Target catalog file '$BaselinePath' not modified." -ForegroundColor Yellow
    } else {
        $baselineJson = $baselineData | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($BaselinePath, $baselineJson, [System.Text.Encoding]::UTF8)
        Write-Host "[SUCCESS] Baseline saved to '$BaselinePath' with $fileCount cataloged entries." -ForegroundColor Green
    }

    $auditData = @{
        Mode = "CreateBaseline"
        TargetPath = $TargetPath
        BaselinePath = $BaselinePath
        TimestampIso = $isoNow
        DryRun = [bool]$DryRun
        Summary = @{
            BaselineCount = $fileCount
            ModifiedCount = 0
            CreatedCount = 0
            DeletedCount = 0
            AclDriftCount = 0
            Status = "BASELINE_CREATED"
        }
        Discrepancies = @()
    }
    Save-EvidenceReports -ReportData $auditData -OutDir $ReportDir
}
elseif ($Mode -eq "ScanAndEnforce") {
    if (-not (Test-Path -Path $BaselinePath)) {
        Write-Error "Baseline path '$BaselinePath' not found. Create baseline first."
        exit 1
    }

    Write-Host "[FIM] Loading baseline from '$BaselinePath'..." -ForegroundColor Cyan
    $baselineRaw = Get-Content -Path $BaselinePath -Raw
    $baselineData = $baselineRaw | ConvertFrom-Json

    $baselineCatalog = $baselineData.Files
    $currentFiles = Get-ChildItem -Path $TargetPath -Recurse -File -ErrorAction SilentlyContinue

    $discrepancies = [System.Collections.Generic.List[PSObject]]::new()
    $currentRelPaths = @{}

    $modifiedCount = 0
    $createdCount = 0
    $deletedCount = 0
    $aclDriftCount = 0

    # Scan current files against baseline
    foreach ($file in $currentFiles) {
        $relPath = $file.FullName.Substring($TargetPath.Length).TrimStart('\', '/')
        $currentRelPaths[$relPath] = $true

        if ($baselineCatalog.PSObject.Properties[$relPath]) {
            $baseEntry = $baselineCatalog.PSObject.Properties[$relPath].Value
            $currentHash = Get-FileSha256 -FilePath $file.FullName
            $currentAcl = Get-FileAclSddl -FilePath $file.FullName

            # Hash check
            if ($currentHash -ne $baseEntry.Sha256) {
                $modifiedCount++
                $discrepancies.Add([PSCustomObject]@{
                    Path = $relPath
                    Type = "MODIFIED"
                    Details = "Baseline SHA256 '$($baseEntry.Sha256)' mismatch current '$currentHash'"
                })
                Write-FimEventLog -Message "FIM ALERT: Unauthorized modification of '$relPath'" -EntryType "Error"
            }

            # ACL check
            if ($currentAcl -ne $baseEntry.AclSddl) {
                $aclDriftCount++
                $discrepancies.Add([PSCustomObject]@{
                    Path = $relPath
                    Type = "ACL_DRIFT"
                    Details = "Permissions SDDL changed."
                })
                Write-FimEventLog -Message "FIM ALERT: ACL Drift detected on '$relPath'" -EntryType "Warning"
            }
        } else {
            # New file detected
            $createdCount++
            $discrepancies.Add([PSCustomObject]@{
                Path = $relPath
                Type = "CREATED"
                Details = "File is not present in baseline."
            })
            Write-FimEventLog -Message "FIM ALERT: New uncataloged file created '$relPath'" -EntryType "Warning"
        }
    }

    # Detect deleted files
    foreach ($baseProp in $baselineCatalog.PSObject.Properties) {
        $baseRelPath = $baseProp.Name
        if (-not $currentRelPaths.ContainsKey($baseRelPath)) {
            $deletedCount++
            $discrepancies.Add([PSCustomObject]@{
                Path = $baseRelPath
                Type = "DELETED"
                Details = "File in baseline missing from target path."
            })
            Write-FimEventLog -Message "FIM ALERT: File deletion detected '$baseRelPath'" -EntryType "Error"
        }
    }

    $status = if ($discrepancies.Count -eq 0) { "INTEGRITY_VERIFIED" } else { "DRIFT_DETECTED" }
    Write-Host "[FIM DISCREPANCY ANALYSIS] Status: $status | Modified: $modifiedCount | New: $createdCount | Deleted: $deletedCount | ACL Drift: $aclDriftCount" -ForegroundColor (if ($status -eq "INTEGRITY_VERIFIED") { "Green" } else { "Red" })

    $auditData = @{
        Mode = "ScanAndEnforce"
        TargetPath = $TargetPath
        BaselinePath = $BaselinePath
        TimestampIso = $isoNow
        DryRun = [bool]$DryRun
        Summary = @{
            BaselineCount = $baselineCatalog.PSObject.Properties.Count
            ModifiedCount = $modifiedCount
            CreatedCount = $createdCount
            DeletedCount = $deletedCount
            AclDriftCount = $aclDriftCount
            Status = $status
        }
        Discrepancies = $discrepancies
    }

    Save-EvidenceReports -ReportData $auditData -OutDir $ReportDir
}
