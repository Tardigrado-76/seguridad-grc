#Requires -Version 5.1
<#
.SYNOPSIS
    BunkerOS — Generador de Secretos para Despliegue (ENS Alta / NIS2)
.DESCRIPTION
    Genera ficheros de secretos criptográficos seguros para Docker Compose.
    Los ficheros se crean en apps/web/secrets/ con permisos restrictivos.
.NOTES
    Ejecutar desde la raíz del proyecto: .\scripts\init-secrets.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SecretsDir = Join-Path $PSScriptRoot "..\apps\web\secrets"

# Crear directorio si no existe
if (-not (Test-Path $SecretsDir)) {
    New-Item -ItemType Directory -Path $SecretsDir -Force | Out-Null
}

Write-Host "`n[*] BunkerOS — Inicializador de Secretos (ENS Alta)" -ForegroundColor Cyan
Write-Host "    Directorio de destino: $SecretsDir`n"

# ─── Helper: Generar secreto aleatorio ────────────────────────────────────────
function New-CryptoSecret {
    param([int]$Bytes = 64)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buffer = New-Object byte[] $Bytes
    $rng.GetBytes($buffer)
    return ($buffer | ForEach-Object { $_.ToString("x2") }) -join ''
}

# ─── 1. BUNKER_MASTER_KEY ────────────────────────────────────────────────────
$masterKeyFile = Join-Path $SecretsDir "bunker_master_key.txt"
if (Test-Path $masterKeyFile) {
    Write-Host "[!] bunker_master_key.txt ya existe — SALTANDO (no se sobreescribe)" -ForegroundColor Yellow
} else {
    $key = New-CryptoSecret -Bytes 64
    Set-Content -Path $masterKeyFile -Value $key -NoNewline -Encoding UTF8
    Write-Host "[+] bunker_master_key.txt generado (512 bits)" -ForegroundColor Green
}

# ─── 2. BUNKER_JWT_SECRET ────────────────────────────────────────────────────
$jwtSecretFile = Join-Path $SecretsDir "bunker_jwt_secret.txt"
if (Test-Path $jwtSecretFile) {
    Write-Host "[!] bunker_jwt_secret.txt ya existe — SALTANDO" -ForegroundColor Yellow
} else {
    $jwt = New-CryptoSecret -Bytes 64
    Set-Content -Path $jwtSecretFile -Value $jwt -NoNewline -Encoding UTF8
    Write-Host "[+] bunker_jwt_secret.txt generado (512 bits)" -ForegroundColor Green
}

# ─── 3. DATABASE_URL ─────────────────────────────────────────────────────────
$dbUrlFile = Join-Path $SecretsDir "database_url.txt"
if (Test-Path $dbUrlFile) {
    Write-Host "[!] database_url.txt ya existe — SALTANDO" -ForegroundColor Yellow
} else {
    $dbPassword = New-CryptoSecret -Bytes 32
    $dbUrl = "postgresql://bunker_user:${dbPassword}@postgres:5432/bunker_db?sslmode=require"
    Set-Content -Path $dbUrlFile -Value $dbUrl -NoNewline -Encoding UTF8
    Write-Host "[+] database_url.txt generado (contraseña de 256 bits)" -ForegroundColor Green
}

# ─── 4. Restringir permisos (solo usuario actual) ────────────────────────────
try {
    Get-ChildItem -Path $SecretsDir -Filter "*.txt" | ForEach-Object {
        $acl = Get-Acl $_.FullName
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser, "FullControl", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $_.FullName -AclObject $acl
    }
    Write-Host "[+] Permisos restrictivos aplicados (solo usuario actual)" -ForegroundColor Green
} catch {
    Write-Host "[!] No se pudieron restringir permisos ACL: $_" -ForegroundColor Yellow
}

# ─── 5. Configurar Hooks de Git de Seguridad (ENS / CRA) ─────────────────────
try {
    Write-Host "`n[*] Configurando Git Hooks de Seguridad..." -ForegroundColor Cyan
    # Ejecutar usando python local
    & python "$PSScriptRoot\setup_git_hooks.py"
} catch {
    Write-Host "[!] No se pudieron configurar los Git Hooks de Seguridad: $_" -ForegroundColor Yellow
}

Write-Host "`n[*] Inicialización completada." -ForegroundColor Cyan
Write-Host "    IMPORTANTE: Estos ficheros NUNCA deben commitearse al repositorio." -ForegroundColor Red
Write-Host "    Verificar que .gitignore contiene 'secrets/*.txt'`n" -ForegroundColor Yellow

