# crear_db_tavilga.ps1
# Crea carpeta, base de datos y tabla para Tavilga (localhost)

$carpetaDB = "C:\n8n_data"
$dbPath = "$carpetaDB\tavilga.sqlite"

# Crear carpeta si no existe
if (!(Test-Path $carpetaDB)) {
    New-Item -ItemType Directory -Path $carpetaDB | Out-Null
    Write-Host "📁 Carpeta creada: $carpetaDB"
}

# Crear base de datos vacía
if (!(Test-Path $dbPath)) {
    Write-Host "🧱 Creando base de datos SQLite..."
    $null = New-Item -ItemType File -Path $dbPath
} else {
    Write-Host "✅ Base de datos ya existe: $dbPath"
}

# Crear tabla (requiere que sqlite3.exe esté en el PATH)
$sql = @"
CREATE TABLE IF NOT EXISTS consultas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    email TEXT NOT NULL,
    mensaje TEXT,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"@

# Descargar SQLite si no está instalado
if (-not (Get-Command sqlite3.exe -ErrorAction SilentlyContinue)) {
    Write-Host "⬇️ Descargando sqlite3.exe..."
    Invoke-WebRequest -Uri "https://www.sqlite.org/2024/sqlite-tools-win-x64-3450100.zip" -OutFile "$env:TEMP\sqlite.zip"
    Expand-Archive "$env:TEMP\sqlite.zip" -DestinationPath "$carpetaDB"
    $env:Path += ";$carpetaDB"
}

Write-Host "⚙️ Creando tabla..."
echo $sql | sqlite3.exe $dbPath
Write-Host "✅ Base de datos y tabla creadas correctamente en $dbPath"
