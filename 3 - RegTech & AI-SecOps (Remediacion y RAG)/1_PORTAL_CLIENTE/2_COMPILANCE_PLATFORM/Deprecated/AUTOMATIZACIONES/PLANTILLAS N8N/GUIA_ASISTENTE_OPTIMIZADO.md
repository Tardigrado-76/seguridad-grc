# 🔧 Guía de Configuración - Asistente Personal OPTIMIZADO

## 📋 Análisis del Workflow Original vs Optimizado

### Workflow Original (`Asistente Personal_webhook.json`):
- ✅ Webhook HTTPS configurado
- ✅ Gemini 2.0 Flash gratuito (OpenRouter)
- ✅ 4 herramientas de Google Calendar
- ⚠️ Email placeholder: `puesto_tu_email@gmail.com`
- ❌ Sin herramientas de Email
- ❌ Sin herramientas de Tasks
- ❌ Nodo "Get a chat" innecesario

### Workflow Optimizado (`Asistente_Personal_OPTIMIZADO.json`):
- ✅ **12 herramientas AI totales**:
  - 📧 3 Gmail (enviar, comprobar, etiquetar)
  - ✅ 4 Google Tasks (crear, listar, completar, eliminar)
  - 📅 4 Google Calendar (crear, eliminar, actualizar, consultar)
- ✅ System prompt mejorado con todas las capacidades
- ✅ Webhook HTTPS configurado
- ✅ Gemini 2.0 Flash gratuito (OpenRouter)
- ✅ Memoria conversacional
- ✅ Transcripción de audio con Whisper
- ✅ Arquitectura limpia sin nodos innecesarios

---

## 🚀 Paso 1: Configurar Webhook en Telegram

El workflow usa **Webhook** en lugar de **Telegram Trigger**. Esto significa que debes registrar manualmente el webhook en Telegram.

### Opción A: Usar n8n Tunnel (Recomendado)

1. **Activar tunnel en n8n**:
   ```
   Settings > n8n API > Enable "Production webhook URL" o "Tunnel"
   ```
   - Obtendrás una URL como: `https://xxxxx.tunnel.n8n.cloud`

2. **Obtener la URL completa del webhook**:
   - En n8n, abre el workflow
   - Haz clic en el nodo "Webhook"
   - Copia la "Production URL": `https://xxxxx.tunnel.n8n.cloud/webhook/asistente-personal-tardigrado`

3. **Registrar webhook en Telegram**:
   ```bash
   curl -X POST "https://api.telegram.org/bot<TU_BOT_TOKEN>/setWebhook" \
     -d "url=https://xxxxx.tunnel.n8n.cloud/webhook/asistente-personal-tardigrado"
   ```
   
   **Reemplaza**:
   - `<TU_BOT_TOKEN>`: Token de tu bot de Telegram (de @BotFather)
   - `https://xxxxx.tunnel.n8n.cloud`: Tu URL del tunnel de n8n

### Opción B: Usar dominio propio con HTTPS

Si tienes n8n en un dominio propio con HTTPS:

```bash
curl -X POST "https://api.telegram.org/bot<TU_BOT_TOKEN>/setWebhook" \
  -d "url=https://tu-dominio.com/webhook/asistente-personal-tardigrado"
```

### Verificar que el webhook está registrado:

```bash
curl "https://api.telegram.org/bot<TU_BOT_TOKEN>/getWebhookInfo"
```

**Respuesta esperada**:
```json
{
  "ok": true,
  "result": {
    "url": "https://xxxxx.tunnel.n8n.cloud/webhook/asistente-personal-tardigrado",
    "has_custom_certificate": false,
    "pending_update_count": 0,
    "max_connections": 40
  }
}
```

---

## 🔑 Paso 2: Configurar Credenciales

El workflow necesita **5 tipos de credenciales**:

### 1. Telegram API (3 nodos)
- **Nodos**: Obtener Audio de Telegram, Enviar Respuesta Telegram
- **Configuración**:
  - **Token**: Tu token de bot de @BotFather
  - Reemplaza `YOUR_TELEGRAM_CREDENTIALS_ID` en el JSON

### 2. OpenAI API (Whisper - 1 nodo)
- **Nodo**: Transcribir audio
- **Configuración**:
  - **API Key**: Tu API key de OpenAI (https://platform.openai.com/api-keys)
  - Reemplaza `YOUR_OPENAI_CREDENTIALS_ID` en el JSON

### 3. OpenRouter API (Gemini - 1 nodo)
- **Nodo**: OpenRouter Chat Model
- **Configuración**:
  - **Base URL**: `https://openrouter.ai/api/v1`
  - **API Key**: Tu API key de OpenRouter (https://openrouter.ai/keys)
  - **Modelo**: `google/gemini-2.0-flash-exp:free` (¡GRATUITO!)
  - Reemplaza `YOUR_OPENROUTER_CREDENTIALS_ID` en el JSON

> [!TIP]
> **OpenRouter** te permite usar Gemini 2.0 Flash **completamente gratis**. No necesitas pagar por tokens de Google.

### 4. Google Calendar OAuth2 (4 nodos)
- **Nodos**: Calendar - Crear evento, Eliminar evento, Actualizar evento, Comprobar disponibilidad
- **Configuración**:
  - Sigue el asistente de OAuth2 de n8n
  - Autoriza el acceso a Google Calendar
  - Reemplaza `YOUR_GOOGLE_CALENDAR_CREDENTIALS_ID` en el JSON
  - **Importante**: Actualiza `TU_EMAIL_AQUI@gmail.com` con tu email real en los 4 nodos

### 5. Gmail OAuth2 (3 nodos)
- **Nodos**: Gmail - Enviar email, Comprobar emails, Añadir etiqueta
- **Configuración**:
  - Sigue el asistente de OAuth2 de n8n
  - Autoriza el acceso a Gmail
  - Reemplaza `YOUR_GMAIL_CREDENTIALS_ID` en el JSON

### 6. Google Tasks OAuth2 (4 nodos)
- **Nodos**: Tasks - Crear tarea, Comprobar tareas pendientes, Completar tarea, Eliminar tarea
- **Configuración**:
  - Sigue el asistente de OAuth2 de n8n
  - Autoriza el acceso a Google Tasks
  - **Obtener ID de tu lista de tareas**:
    1. En n8n, crea un nodo temporal "Google Tasks"
    2. Operación: "Get All Lists"
    3. Ejecuta el nodo
    4. Copia el ID de tu lista (ej: `MDMzNjI2NzQwMTkzMDU3MTE3NTU6MDow`)
    5. Reemplaza `YOUR_GOOGLE_TASKS_LIST_ID` en los 4 nodos de Tasks

---

## ⚙️ Paso 3: Actualizar IDs en el Workflow

Antes de importar, actualiza estos valores en el archivo JSON:

### Buscar y reemplazar en el archivo:

| Buscar | Reemplazar con |
|--------|----------------|
| `TU_EMAIL_AQUI@gmail.com` | Tu email de Google Calendar (4 ocurrencias) |
| `YOUR_GOOGLE_TASKS_LIST_ID` | El ID de tu lista de Google Tasks (4 ocurrencias) |
| `YOUR_TELEGRAM_CREDENTIALS_ID` | ID de tu credencial de Telegram en n8n |
| `YOUR_OPENAI_CREDENTIALS_ID` | ID de tu credencial de OpenAI en n8n |
| `YOUR_OPENROUTER_CREDENTIALS_ID` | ID de tu credencial de OpenRouter en n8n |
| `YOUR_GOOGLE_CALENDAR_CREDENTIALS_ID` | ID de tu credencial de Google Calendar en n8n |
| `YOUR_GMAIL_CREDENTIALS_ID` | ID de tu credencial de Gmail en n8n |
| `YOUR_GOOGLE_TASKS_CREDENTIALS_ID` | ID de tu credencial de Google Tasks en n8n |

> [!NOTE]
> Los IDs de credenciales los encuentras en n8n > Credentials. Cada credencial tiene un ID único.

---

## ✅ Paso 4: Importar y Activar

1. **Importar en n8n**:
   - n8n > + > Import from file
   - Selecciona `Asistente_Personal_OPTIMIZADO.json`

2. **Verificar configuración**:
   - Todos los nodos sin errores rojos ✅
   - Todas las credenciales configuradas ✅
   - Email de Calendar actualizado ✅
   - ID de Google Tasks actualizado ✅

3. **Activar el workflow**:
   - Toggle "Active" > ON
   - El webhook estará escuchando

---

## 🧪 Paso 5: Probar

### Enviar mensaje de prueba:

1. **Abre Telegram**
2. **Busca tu bot**
3. **Envía**: `Hola, ¿qué puedes hacer?`

**Respuesta esperada**:
El bot te describe sus capacidades (Email, Tasks, Calendar, Audio).

### Pruebas específicas:

#### 📅 Calendario:
```
"Crea un evento mañana a las 10am: Reunión con el equipo"
"¿Qué eventos tengo esta semana?"
"Elimina el evento [nombre]"
```

#### ✅ Tareas:
```
"Crea una tarea: Revisar documentos del proyecto"
"¿Qué tareas tengo pendientes?"
"Marca como completada la tarea [nombre]"
"Elimina la tarea [nombre]"
```

#### 📧 Email:
```
"Envía un email a test@example.com con asunto: Prueba y mensaje: Hola"
"¿Tengo emails sin leer de hoy?"
```

#### 🎤 Audio:
- Envía un mensaje de voz
- El bot transcribirá automáticamente y responderá

---

## 🔍 Debugging

### Ver logs del webhook:

1. **En n8n**: Pestaña "Executions"
2. **Filtrar por**: "Asistente Personal - OPTIMIZADO"
3. **Ver ejecuciones**: Cada mensaje de Telegram crea una ejecución

### Problemas comunes:

| Error | Solución |
|-------|----------|
| "Webhook not responding" | Verifica que el webhook esté registrado en Telegram |
| "Invalid credentials" | Reconfigura las credenciales OAuth2 |
| "Calendar not found" | Actualiza el email en los nodos de Calendar |
| "Task list not found" | Actualiza el ID de la lista en los nodos de Tasks |
| "OpenRouter API error" | Verifica tu API key de OpenRouter |

### Verificar webhook en Telegram:

```bash
curl "https://api.telegram.org/bot<TU_BOT_TOKEN>/getWebhookInfo"
```

---

## 🎨 Comparativa de Mejoras

| Característica | Original | Optimizado |
|----------------|----------|------------|
| **Herramientas AI** | 4 | **12** ✨ |
| **Email** | ❌ | ✅ 3 herramientas |
| **Tasks** | ❌ | ✅ 4 herramientas |
| **Calendar** | ✅ 4 | ✅ 4 herramientas |
| **System Prompt** | Básico | **Detallado** ✨ |
| **Arquitectura** | Nodo innecesario | **Limpia** ✨ |
| **Modelo AI** | Gemini 2.0 Flash | Gemini 2.0 Flash |
| **Coste** | Gratis | **Gratis** 🎉 |

---

## 💡 Ventajas de usar OpenRouter + Gemini

1. **Completamente GRATUITO**: `google/gemini-2.0-flash-exp:free`
2. **Sin necesidad de Google Cloud**: No requieres cuenta de pago de Google
3. **Compatible con OpenAI API**: Misma interfaz que GPT
4. **Rápido y eficiente**: Gemini 2.0 Flash es muy veloz
5. **Límites generosos**: Suficiente para uso personal

---

## 📊 Capacidades Finales

### 📧 Email (Gmail)
- ✅ Enviar correos electrónicos
- ✅ Comprobar emails no leídos con filtros
- ✅ Añadir etiquetas a emails

### ✅ Tareas (Google Tasks)
- ✅ Crear nuevas tareas
- ✅ Listar tareas pendientes
- ✅ Marcar tareas como completadas
- ✅ Eliminar tareas

### 📅 Calendario (Google Calendar)
- ✅ Crear eventos con fecha, hora y descripción
- ✅ Consultar disponibilidad en rangos de fechas
- ✅ Actualizar eventos existentes
- ✅ Eliminar eventos

### 🗣️ Audio
- ✅ Transcribir mensajes de voz con Whisper

### 🧠 Memoria
- ✅ Recordar conversaciones anteriores por usuario (chat_id)

---

**¡Tu asistente personal está listo! 🚀**

*by Tardigrado | Powered by n8n + Gemini 2.0 Flash*
