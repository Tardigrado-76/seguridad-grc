# ============================================================
# Bunker HQ - Auditoria Final y Sellado Soberano (Paso 5.1)
# Ejecuta npm audit, Trivy y genera el SBOM CycloneDX del ecosistema.
# Normativa: ENS Categoria Alta, CRA Art.13, NIS2 Art.21
# ============================================================
Requires -Version 5.1

$ROOT   = "e:\PROYECTOS IA\Release_Builder"
$BFF    = "$ROOT\bunker-hq-bff"
$FE     = "$ROOT\bunker-hq-frontend"
$DIST   = "$ROOT\dist\03_Security_Audits"
$DATE   = Get-Date -Format "yyyy-MM-dd_HHmm"

$ErrorActionPreference = "Continue"

function Write-Banner([string]$text) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Invoke-Step([string]$label, [scriptblock]$block) {
    Write-Host "[$label] Iniciando..." -ForegroundColor Yellow
    & $block
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[$label] Warning/Error (codigo $LASTEXITCODE)" -ForegroundColor Yellow
    } else {
        Write-Host "[$label] OK" -ForegroundColor Green
    }
}

# Ensure output directory exists
if (!(Test-Path $DIST)) {
    New-Item -ItemType Directory -Path $DIST -Force | Out-Null
}

# --- 1. NPM AUDIT - Frontend ----------------------------------------------
Write-Banner "1/4 - npm audit (Frontend)"
Invoke-Step "npm-audit-frontend" {
    Push-Location $FE
    $raw = npm audit --json 2>&1
    $raw | Out-File "$DIST\npm_audit_frontend_$DATE.json" -Encoding utf8
    $out = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
    Pop-Location
    if ($out -and $out.metadata -and $out.metadata.vulnerabilities) {
        Write-Host "   Vulnerabilidades: Criticas=$($out.metadata.vulnerabilities.critical) Altas=$($out.metadata.vulnerabilities.high)"
        if ($out.metadata.vulnerabilities.critical -gt 0) {
            Write-Host "   [!] CVE Critico detectado en Frontend. Abortando compilacion." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "   [!] No se pudo parsear el resultado de npm audit (Frontend)." -ForegroundColor Yellow
    }
}

# --- 2. NPM AUDIT - BFF Nest.js -------------------------------------------
Write-Banner "2/4 - npm audit (BFF Nest.js)"
Invoke-Step "npm-audit-bff" {
    Push-Location $BFF
    $raw = npm audit --json 2>&1
    $raw | Out-File "$DIST\npm_audit_bff_$DATE.json" -Encoding utf8
    $out = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
    Pop-Location
    if ($out -and $out.metadata -and $out.metadata.vulnerabilities) {
        Write-Host "   Vulnerabilidades: Criticas=$($out.metadata.vulnerabilities.critical) Altas=$($out.metadata.vulnerabilities.high)"
        if ($out.metadata.vulnerabilities.critical -gt 0) {
            Write-Host "   [!] CVE Critico detectado en BFF. Abortando compilacion." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "   [!] No se pudo parsear el resultado de npm audit (BFF)." -ForegroundColor Yellow
    }
}

# --- 3. SBOM CycloneDX (Python Core - FastAPI) ----------------------------
Write-Banner "3/4 - SBOM CycloneDX (Python Core)"
Invoke-Step "cyclonedx-python" {
    & "$ROOT\.venv\Scripts\python.exe" -m cyclonedx_py environment `
        --of JSON -o "$DIST\sbom_python_core_$DATE.json" 2>&1
    Write-Host "   Core Python SBOM generado en: dist/03_Security_Audits/sbom_python_core_$DATE.json"
}

# --- 4. TRIVY - Escaneo de contenedores y sistema de archivos -------------
Write-Banner "4/4 - Trivy (SCA + Filesystem)"
$trivyBin = Get-Command trivy -ErrorAction SilentlyContinue
if ($trivyBin) {
    Invoke-Step "trivy-frontend" {
        trivy fs "$FE" `
            --format cyclonedx `
            --output "$DIST\trivy_sbom_frontend_$DATE.json" `
            --severity CRITICAL,HIGH `
            --quiet
        Write-Host "   Trivy SBOM Frontend: dist/03_Security_Audits/trivy_sbom_frontend_$DATE.json"
    }
    Invoke-Step "trivy-bff" {
        trivy fs "$BFF" `
            --format cyclonedx `
            --output "$DIST\trivy_sbom_bff_$DATE.json" `
            --severity CRITICAL,HIGH `
            --quiet
        Write-Host "   Trivy SBOM BFF: dist/03_Security_Audits/trivy_sbom_bff_$DATE.json"
    }
} else {
    Write-Host "   [!] Trivy no encontrado en PATH. Saltando escaneo." -ForegroundColor Yellow
}

Write-Banner "AUDITORIA COMPLETADA"
Write-Host "Artefactos guardados en: $DIST" -ForegroundColor Green
Write-Host "Fecha: $DATE"
