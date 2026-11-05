# ============================================================
# Bunker HQ - Congelacion del Perimetro y Custodia Fisica (Paso 4.3b)
# Congela las ramas de codigo y vuelca el entorno al SSD de custodia.
# Normativa: ENS Categoria Alta, Esquema de Copias de Seguridad CCN-STIC 814
# ============================================================
#Requires -Version 5.1

$ROOT    = "e:\PROYECTOS IA\Release_Builder"
$DEST    = "F:\Backups\BunkerOS_MVP"  # SSD de asalto
$DATE    = Get-Date -Format "yyyy-MM-dd_HHmm"
$LOGFILE = "$ROOT\dist\03_Security_Audits\robocopy_$DATE.log"

$ErrorActionPreference = "Stop"

function Write-Banner([string]$text) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Magenta
    Write-Host "  $text" -ForegroundColor Magenta
    Write-Host ("=" * 60) -ForegroundColor Magenta
    Write-Host ""
}

# --- 1. VERIFICAR REPOSITORIO GIT LIMPIO ---------------------------------
Write-Banner "1/4 - Verificacion del estado Git"
Push-Location $ROOT

$status = git status --porcelain
if ($status) {
    Write-Host " [!] Hay cambios sin commitear:" -ForegroundColor Yellow
    git status --short
    $confirm = Read-Host "¿Continuar de todos modos? (s/N)"
    if ($confirm -ne 's') { Write-Host "Abortado."; exit 1 }
} else {
    Write-Host "   Repositorio limpio (working tree clean)" -ForegroundColor Green
}

# --- 2. ETIQUETAR LA VERSION DE SELLADO ----------------------------------
Write-Banner "2/4 - Etiquetado de version de sellado"
$TAG = "release/sealed-$DATE"
git tag -f -a $TAG -m "Sellado soberano: $DATE | Fase 4 completada"
Write-Host "   Tag creado: $TAG" -ForegroundColor Green
Pop-Location

# --- 3. VOLCADO ROBOCOPY AL SSD DE CUSTODIA ------------------------------
Write-Banner "3/4 - Volcado Robocopy -> $DEST"

# Crear destino si no existe
if (!(Test-Path $DEST)) {
    New-Item -ItemType Directory -Path $DEST -Force | Out-Null
}

# Exclusiones: node_modules, .venv, __pycache__, .git objects grandes
$excludeDir = @("node_modules", ".venv", "__pycache__", ".git")
$excludeFile = @("*.pyc", "*.log")

# Robocopy para clonacion local segura
robocopy "$ROOT" "$DEST" `
    /E `
    /COPY:DAT `
    /DCOPY:DAT `
    /XD $excludeDir `
    /XF $excludeFile `
    /R:2 /W:5 `
    /LOG:"$LOGFILE" `
    /NP /TEE

$rc = $LASTEXITCODE
# Robocopy: codigos < 8 son exito
if ($rc -lt 8) {
    Write-Host "   Volcado completado correctamente (codigo $rc)" -ForegroundColor Green
    Write-Host "   Destino: $DEST"
    Write-Host "   Log:     $LOGFILE"
} else {
    Write-Host "   Robocopy fallo con codigo $rc. Revisar log: $LOGFILE" -ForegroundColor Red
    exit 1
}

# --- 4. GENERAR HASH DE INTEGRIDAD DEL VOLCADO ---------------------------
Write-Banner "4/4 - Hash SHA3-512 de integridad del volcado"

$hashManifest = "$DEST\_INTEGRITY_MANIFEST_$DATE.txt"
Write-Host "Generando manifiesto de integridad..." -ForegroundColor Yellow

Get-ChildItem -Path $DEST -Recurse -File |
    Where-Object { $_.FullName -notlike "*node_modules*" -and $_.FullName -notlike "*.git*" -and $_.Name -notlike "_INTEGRITY*" } |
    ForEach-Object {
        $hash = Get-FileHash $_.FullName -Algorithm SHA384
        "$($hash.Hash)  $($_.FullName.Replace($DEST, '.'))"
    } | Out-File $hashManifest -Encoding utf8

Write-Host "   Manifiesto de integridad: $hashManifest" -ForegroundColor Green

Write-Banner "SELLADO SOBERANO COMPLETADO"
Write-Host "   Custodia fisica: $DEST" -ForegroundColor Green
Write-Host "   Tag Git:         $TAG" -ForegroundColor Green
Write-Host "   Log Robocopy:    $LOGFILE" -ForegroundColor Green
Write-Host "   Manifiesto SHA384: $hashManifest" -ForegroundColor Green
