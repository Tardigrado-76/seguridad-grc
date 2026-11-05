@echo off
title Tavilga - n8n Localhost Service
color 0A

:: Ruta base de instalación n8n
set "N8N_PATH=%USERPROFILE%\AppData\Roaming\npm\node_modules\n8n\bin\n8n"

:: Verificar instalación de Node.js y n8n
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Node.js no encontrado. Descarga desde https://nodejs.org
    pause
    exit /b
)
where n8n >nul 2>nul
if %errorlevel% neq 0 (
    echo ⬇️ Instalando n8n globalmente...
    npm install -g n8n
)

:: Variables de entorno (Se sugiere cargar desde un archivo .env seguro)
:: NO utilizar setx para secretos, ya que los guarda en texto plano en el Registro de Windows.
set N8N_PORT=5678
set N8N_BASIC_AUTH_ACTIVE=true
:: IMPORTANTE: Cambiar estas contraseñas en un archivo .env no trackeado
set N8N_BASIC_AUTH_USER=admin
set N8N_BASIC_AUTH_PASSWORD=tavilga2025_SECURE_CHANGE_ME
set N8N_EDITOR_BASE_URL=http://localhost:5678/
set N8N_ENCRYPTION_KEY=TavilgaLocalSecureKey2025_CHANGE_ME
set N8N_PROTOCOL=http
set N8N_HOST=localhost

:: Mostrar configuración
echo.
echo ================================================
echo 🚀 Iniciando servicio n8n para Tavilga.es
echo -----------------------------------------------
echo Puerto: 5678
echo Usuario: admin
echo Password: tavilga2025
echo Base URL: http://localhost:5678/
echo ================================================
echo.

:: Iniciar n8n de forma continua (24/7)
:run
echo Iniciando n8n...
n8n start
timeout /t 10
goto run
