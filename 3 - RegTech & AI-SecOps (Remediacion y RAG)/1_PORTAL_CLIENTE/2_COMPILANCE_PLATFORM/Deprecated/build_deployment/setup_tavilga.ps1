# Tavilga n8n Production Setup Script
param(
    [string]$EnvPath = "C:\tavilga\n8n\.env",
    [string]$DbPath = "C:\tavilga\n8n\tavilga.db"
)

Write-Host "=== Creando estructura de carpetas... ==="
New-Item -ItemType Directory -Force -Path "C:\tavilga\n8n"

Write-Host "=== Creando base de datos SQLite... ==="
if (!(Test-Path $DbPath)) {
    $connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$DbPath;Version=3;")
    $connection.Open()
    $command = $connection.CreateCommand()
    $command.CommandText = "CREATE TABLE IF NOT EXISTS consultas (id INTEGER PRIMARY KEY, nombre TEXT, email TEXT, mensaje TEXT, fecha DATETIME DEFAULT CURRENT_TIMESTAMP);"
    $command.ExecuteNonQuery()
    $connection.Close()
    Write-Host "Base de datos creada en: $DbPath"
} else {
    Write-Host "Base de datos ya existe: $DbPath"
}

Write-Host "=== Creando archivo .env si no existe... ==="
if (!(Test-Path $EnvPath)) {
    Set-Content -Path $EnvPath -Value (Get-Content ".env")
    Write-Host "Archivo .env copiado a: $EnvPath"
} else {
    Write-Host "Archivo .env ya existe."
}

Write-Host "=== Instalación completada ==="
