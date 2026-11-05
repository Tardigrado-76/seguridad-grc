# BunkerOS Pre-Build Test and Security Pipeline
# Verifies health, static security profile, and supply chain integrity.

$ErrorActionPreference = "Stop"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Starting BunkerOS Pre-Build Pipeline..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Set testing environment variables
$env:BUNKER_MASTER_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
$env:BUNKER_JWT_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Ensure virtual environment is active/resolved
$pythonPath = ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonPath)) {
    $pythonPath = "python"
}

# 1. Run Unit/Integration Tests
Write-Host "`n[1/3] Running automated tests with pytest..." -ForegroundColor Yellow
$env:PYTHONPATH = (Get-Location).Path
& $pythonPath -m pytest tests/
if ($LASTEXITCODE -ne 0) {
    Write-Error "pytest suite failed! Aborting pipeline."
    exit 1
}
Write-Host "[+] Pytest completed successfully." -ForegroundColor Green

# 2. Run Static Analysis (Bandit)
Write-Host "`n[2/3] Running static analysis with Bandit (CWE-20/208)..." -ForegroundColor Yellow
$banditPath = ".venv\Scripts\bandit.exe"
if (-not (Test-Path $banditPath)) {
    $banditPath = "bandit"
}
& $banditPath -c bandit_cwe.yaml -p cwe_strict -r src/
if ($LASTEXITCODE -ne 0) {
    Write-Error "Bandit scan detected critical CWE violations! Aborting pipeline."
    exit 1
}
Write-Host "[+] Bandit scan completed with no violations." -ForegroundColor Green

# 3. Run Supply Chain Audit (CISA KEV)
Write-Host "`n[3/3] Running supply chain validation against CISA KEV..." -ForegroundColor Yellow

# 3a. Generate SBOM (CycloneDX) from current environment
Write-Host "  [3a] Generating SBOM via cyclonedx-py..." -ForegroundColor DarkYellow
& $pythonPath -m cyclonedx_py environment --of JSON -o bom.json 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "SBOM generation failed! Cannot proceed with supply chain audit."
    exit 1
}
Write-Host "  [+] bom.json generated successfully." -ForegroundColor DarkGreen

# 3b. Cross-reference SBOM against CISA KEV catalog
Write-Host "  [3b] Cross-referencing against CISA KEV catalog..." -ForegroundColor DarkYellow
& $pythonPath verify_cisa_kev.py bom.json
if ($LASTEXITCODE -ne 0) {
    Write-Error "CISA KEV validation failed! Actively exploited CVE detected in dependencies."
    exit 1
}
Write-Host "[+] Supply chain integrity verified." -ForegroundColor Green

Write-Host "`n==================================================" -ForegroundColor Green
Write-Host "Pre-Build Pipeline PASSED. Safe to compile." -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
exit 0
