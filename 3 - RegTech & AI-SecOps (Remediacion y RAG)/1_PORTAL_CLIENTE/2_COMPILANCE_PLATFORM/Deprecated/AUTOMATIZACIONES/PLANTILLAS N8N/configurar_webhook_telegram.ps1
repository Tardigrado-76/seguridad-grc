# Script de Configuracion de Webhook para Telegram
# Usar con PowerShell

# Token de bot de Telegram
$TELEGRAM_BOT_TOKEN = "8454970710:AAH_-8wPX1a0YIUPeufNwm4h9Ynxx_LsZBk"

# URL del webhook de n8n
$WEBHOOK_URL = "https://tunnel.n8n.cloud/webhook/asistente-personal-tardigrado"

Write-Host "=== Configuracion de Webhook para Telegram ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Token: $($TELEGRAM_BOT_TOKEN.Substring(0, 10))..." -ForegroundColor Green
Write-Host "Webhook URL: $WEBHOOK_URL" -ForegroundColor Green
Write-Host ""

# 1. Eliminar webhook anterior
Write-Host "1. Eliminando webhook anterior..." -ForegroundColor Yellow
$deleteUrl = "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/deleteWebhook"
try {
    $deleteResponse = Invoke-RestMethod -Uri $deleteUrl -Method Post
    if ($deleteResponse.ok) {
        Write-Host "   OK: Webhook anterior eliminado" -ForegroundColor Green
    }
}
catch {
    Write-Host "   INFO: No habia webhook anterior" -ForegroundColor Gray
}

# 2. Configurar nuevo webhook
Write-Host "2. Configurando nuevo webhook..." -ForegroundColor Yellow
$setWebhookUrl = "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook"
$body = @{
    url = $WEBHOOK_URL
}

try {
    $setResponse = Invoke-RestMethod -Uri $setWebhookUrl -Method Post -Body $body
    if ($setResponse.ok) {
        Write-Host "   OK: Webhook configurado correctamente" -ForegroundColor Green
        Write-Host "   Descripcion: $($setResponse.description)" -ForegroundColor Cyan
    }
    else {
        Write-Host "   ERROR: al configurar webhook" -ForegroundColor Red
        Write-Host "   $($setResponse.description)" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "   ERROR: de conexion: $_" -ForegroundColor Red
    exit 1
}

# 3. Verificar webhook
Write-Host "3. Verificando webhook..." -ForegroundColor Yellow
$getWebhookUrl = "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getWebhookInfo"

try {
    $webhookInfo = Invoke-RestMethod -Uri $getWebhookUrl -Method Get
    if ($webhookInfo.ok) {
        Write-Host ""
        Write-Host "=== INFORMACION DEL WEBHOOK ===" -ForegroundColor Cyan
        Write-Host "URL: $($webhookInfo.result.url)" -ForegroundColor White
        Write-Host "Certificado personalizado: $($webhookInfo.result.has_custom_certificate)" -ForegroundColor White
        Write-Host "Actualizaciones pendientes: $($webhookInfo.result.pending_update_count)" -ForegroundColor White
        Write-Host "Maximo de conexiones: $($webhookInfo.result.max_connections)" -ForegroundColor White
        
        if ($webhookInfo.result.last_error_message) {
            Write-Host "Ultimo error: $($webhookInfo.result.last_error_message)" -ForegroundColor Red
        }
        else {
            Write-Host "Sin errores OK" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "=== CONFIGURACION COMPLETADA ===" -ForegroundColor Green
        Write-Host "Ahora puedes enviar mensajes a tu bot en Telegram" -ForegroundColor Cyan
        Write-Host ""
    }
}
catch {
    Write-Host "   ERROR: al obtener informacion: $_" -ForegroundColor Red
}
