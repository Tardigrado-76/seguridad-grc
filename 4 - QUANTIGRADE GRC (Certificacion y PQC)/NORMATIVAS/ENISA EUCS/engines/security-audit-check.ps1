#Requires -Version 5.1
<#
.SYNOPSIS
    BunkerOS - Security Controls Validation (ENS Alta)
.DESCRIPTION
    Verifies all security controls from Phases 1-6 are active.
.NOTES
    Run from project root: .\scripts\security-audit-check.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PassCount = 0
$FailCount = 0
$Results = @()

function Test-Check {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Normative,
        [bool]$Passed,
        [string]$Detail = ""
    )
    $status = if ($Passed) { "PASS" } else { "FAIL" }
    $color = if ($Passed) { "Green" } else { "Red" }

    if ($Passed) { $script:PassCount++ } else { $script:FailCount++ }

    $line = "  [$status] $Id - $Name ($Normative)"
    if ($Detail) { $line = $line + " | " + $Detail }
    Write-Host $line -ForegroundColor $color
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   BunkerOS - Security Controls Validation (ENS Alta)           " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ================================================================
# SECTION 1: SECRETS
# ================================================================
Write-Host "--- Secrets and Credentials ---" -ForegroundColor White

$gitignore = Get-Content (Join-Path $ProjectRoot ".gitignore") -Raw -ErrorAction SilentlyContinue
Test-Check "SEC-001" ".gitignore excluye .env" "ENS mp.si.3" `
    ($gitignore -match '\.env')

Test-Check "SEC-002" ".gitignore excluye secrets/" "ENS mp.si.3" `
    ($gitignore -match 'secrets/')

Test-Check "SEC-003" ".gitignore excluye *.db" "ENS mp.si.3" `
    ($gitignore -match '\*\.db')

Test-Check "SEC-004" "Directorio secrets/ existe" "CRA" `
    (Test-Path (Join-Path $ProjectRoot "apps\web\secrets"))

$envExample = Get-Content (Join-Path $ProjectRoot ".env.example") -Raw -ErrorAction SilentlyContinue
Test-Check "SEC-005" ".env.example contiene BUNKER_JWT_SECRET" "ENS op.acc.5" `
    ($envExample -match 'BUNKER_JWT_SECRET')

Test-Check "SEC-006" ".env.example contiene DATABASE_URL" "ENS mp.si.3" `
    ($envExample -match 'DATABASE_URL')

# ================================================================
# SECTION 2: DATABASE
# ================================================================
Write-Host "`n--- Database Security ---" -ForegroundColor White

$schema = Get-Content (Join-Path $ProjectRoot "schema.sql") -Raw -ErrorAction SilentlyContinue
Test-Check "DB-001" "RLS habilitado en schema.sql" "ENS op.acc.6" `
    ($schema -match 'ENABLE ROW LEVEL SECURITY')

Test-Check "DB-002" "FORCE RLS activo (Zero-Trust)" "ENS op.acc.6" `
    ($schema -match 'FORCE ROW LEVEL SECURITY')

$dbTs = Get-Content (Join-Path $ProjectRoot "apps\web\lib\db.ts") -Raw -ErrorAction SilentlyContinue
Test-Check "DB-003" "Cifrado AES-256-GCM en db.ts" "RGPD Art.32" `
    ($dbTs -match 'aes-256-gcm')

Test-Check "DB-004" "Contexto RLS por transaccion" "ENS op.acc.6" `
    ($dbTs -match 'SET LOCAL bunker')

# ================================================================
# SECTION 3: AUTHENTICATION
# ================================================================
Write-Host "`n--- Authentication and Session ---" -ForegroundColor White

$authRoute = Get-Content (Join-Path $ProjectRoot "apps\web\app\api\auth\route.ts") -Raw -ErrorAction SilentlyContinue
Test-Check "AUTH-001" "JWT emision con jose (SignJWT)" "ENS op.acc.5" `
    ($authRoute -match 'SignJWT')

Test-Check "AUTH-002" "Cookie HttpOnly en login" "OWASP ASVS 3.4" `
    ($authRoute -match 'httpOnly:\s*true')

Test-Check "AUTH-003" "Cookie SameSite Strict" "OWASP ASVS 3.4" `
    ($authRoute -match "sameSite:\s*'strict'")

Test-Check "AUTH-004" "Endpoint logout existe" "ENS op.acc.5" `
    ($authRoute -match "action === 'logout'")

Test-Check "AUTH-005" "Sin console.log de datos sensibles" "ENS mp.si.3" `
    (-not ($authRoute -match 'console\.log.*MOCK EMAIL'))

$middleware = Join-Path $ProjectRoot "apps\web\middleware.ts"
Test-Check "AUTH-006" "Edge Middleware JWT existe" "ENS op.acc.1" `
    (Test-Path $middleware)

Test-Check "AUTH-007" "bcrypt para hashing passwords" "ENS op.acc.5" `
    ($authRoute -match 'bcrypt')

$fastapiServer = Get-Content (Join-Path $ProjectRoot "src\fastapi_server.py") -Raw -ErrorAction SilentlyContinue
Test-Check "AUTH-008" "Argon2id en FastAPI" "ENS op.acc.5" `
    ($fastapiServer -match 'PasswordHasher')

# ================================================================
# SECTION 4: TRANSPORT
# ================================================================
Write-Host "`n--- Transport and Headers ---" -ForegroundColor White

$nginx = Get-Content (Join-Path $ProjectRoot "apps\web\nginx.conf") -Raw -ErrorAction SilentlyContinue
Test-Check "TLS-001" "Nginx: TLS 1.3 configurado" "ENS mp.com.2" `
    ($nginx -match 'TLSv1\.3')

Test-Check "TLS-002" "Nginx: sin TLS 1.2 fallback" "CCN-STIC 807" `
    (-not ($nginx -match 'TLSv1\.2'))

Test-Check "TLS-003" "Nginx: HSTS con preload" "ENS mp.com.2" `
    ($nginx -match 'preload')

Test-Check "TLS-004" "Nginx: OCSP stapling activo" "ENS mp.com.2" `
    ($nginx -match 'ssl_stapling on')

Test-Check "TLS-005" "Nginx: session tickets deshabilitados" "PFS" `
    ($nginx -match 'ssl_session_tickets off')

Test-Check "TLS-006" "Nginx: server_tokens off" "OWASP" `
    ($nginx -match 'server_tokens off')

# ================================================================
# SECTION 5: CORS
# ================================================================
Write-Host "`n--- CORS and API Security ---" -ForegroundColor White

Test-Check "CORS-001" "Sin allow_methods wildcard en FastAPI" "ENS mp.com.2" `
    (-not ($fastapiServer -match 'allow_methods=\["\*"\]'))

Test-Check "CORS-002" "Sin allow_headers wildcard en FastAPI" "ENS mp.com.2" `
    (-not ($fastapiServer -match 'allow_headers=\["\*"\]'))

Test-Check "API-001" "Rate limiting Token Bucket" "NIS2 Art.21" `
    ($fastapiServer -match 'TokenBucketLimiter')

Test-Check "API-002" "Sanitizacion Pydantic activa" "OWASP A03" `
    ($fastapiServer -match 'SanitizedBaseModel')

# ================================================================
# SECTION 6: INFRASTRUCTURE
# ================================================================
Write-Host "`n--- Infrastructure and Deployment ---" -ForegroundColor White

$rootCompose = Get-Content (Join-Path $ProjectRoot "docker-compose.yml") -Raw -ErrorAction SilentlyContinue
Test-Check "INFRA-001" "Docker: sin passwords inline en compose" "ENS mp.si.3" `
    ($rootCompose -match 'POSTGRES_PASSWORD:.*\$\{')

Test-Check "INFRA-002" "Docker: network isolation (internal)" "NIS2" `
    ($rootCompose -match 'internal:\s*true')

Test-Check "INFRA-003" "Docker: no-new-privileges en DB" "CRA" `
    ($rootCompose -match 'no-new-privileges')

Test-Check "INFRA-004" "Docker: Vault con TLS" "ENS mp.com.2" `
    ($rootCompose -match 'tls_cert_file')

$stagingCompose = Get-Content (Join-Path $ProjectRoot "apps\web\docker-compose.staging.yml") -Raw -ErrorAction SilentlyContinue
Test-Check "INFRA-005" "Staging: Docker Secrets configurados" "ENS mp.si.3" `
    ($stagingCompose -match 'secrets:')

# ================================================================
# SECTION 7: COMPLIANCE
# ================================================================
Write-Host "`n--- Compliance and Disclosure ---" -ForegroundColor White

Test-Check "CRA-001" "security.txt existe (RFC 9116)" "CRA Art.13" `
    (Test-Path (Join-Path $ProjectRoot "apps\web\public\.well-known\security.txt"))

Test-Check "CRA-002" "Incident Response Plan existe" "NIS2 Art.23" `
    (Test-Path (Join-Path $ProjectRoot "compliance\INCIDENT_RESPONSE_PLAN_NIS2.md"))

Test-Check "CRA-003" "SBOM pipeline en CI/CD" "CRA Art.13" `
    (Test-Path (Join-Path $ProjectRoot ".github\workflows\wack-cert.yml"))

$layout = Get-Content (Join-Path $ProjectRoot "apps\web\app\layout.tsx") -Raw -ErrorAction SilentlyContinue
Test-Check "META-001" "Layout: noindex/nofollow (app interna)" "RGPD" `
    ($layout -match 'index:\s*false')

# ================================================================
# SUMMARY
# ================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
$total = $PassCount + $FailCount
$pct = if ($total -gt 0) { [math]::Round(($PassCount / $total) * 100, 1) } else { 0 }

if ($FailCount -eq 0) {
    Write-Host "  RESULT: $PassCount/$total controls PASSED ($pct%) - COMPLIANT" -ForegroundColor Green
} else {
    Write-Host "  RESULT: $PassCount/$total controls PASSED ($pct%)" -ForegroundColor Yellow
    Write-Host "  $FailCount controls FAILED - REMEDIATION REQUIRED" -ForegroundColor Red
}
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if ($FailCount -gt 0) { exit 1 } else { exit 0 }
