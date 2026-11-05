# 🚀 INSTRUCCIONES FINALES - Configuración del Asistente Personal

## ✅ Configuraciones Completadas

- ✅ **Email de Calendar**: `subscribe.catalog@gmail.com` configurado en los 4 nodos
- ✅ **System Prompt**: Actualizado (sin referencias a Google Tasks)
- ✅ **Token de Telegram**: Configurado en el script
- ✅ **Workflow**: Optimizado y listo para importar

## ⚠️ Pendientes de Configurar

### 1. Activar n8n y obtener URL del Tunnel

**El problema actual**: La URL `https://tunnel.n8n.cloud` está incompleta. Necesita un subdominio único.

**Pasos a seguir**:

1. **Inicia n8n**:
   ```powershell
   n8n start
   ```
   O si lo tienes instalado con npm:
   ```powershell
   npx n8n
   ```

2. **Abre n8n en el navegador**:
   ```
   http://localhost:5678
   ```

3. **Activa el Tunnel**:
   - Ve a `Settings` (⚙️ en la barra lateral)
   - Haz clic en `n8n API`
   - Activa `Production webhook URL` o `Tunnel`
   - **COPIA LA URL COMPLETA** que aparece (será algo como: `https://xxxxxxx-xxxx-xxxx.tunnel.n8n.cloud`)

4. **Importa el workflow**:
   - En n8n, haz clic en `+` > `Import from file`
   - Selecciona: `Asistente_Personal_OPTIMIZADO.json`
   - Importa el workflow

5. **Verifica la URL del webhook**:
   - En el workflow importado, haz clic en el nodo `Webhook`
   - Verás la `Production URL`, cópiala
   - Ejemplo: `https://xxxxxxx-xxxx-xxxx.tunnel.n8n.cloud/webhook/asistente-personal-tardigrado`

---

### 2. Actualizar Script de Webhook

Una vez tengas la URL completa del tunnel de n8n:

1. **Edita el script**:
   ```powershell
   notepad "c:\Users\Tardigrado\Desktop\TAVILGA\PLANTILLAS N8N\configurar_webhook_telegram.ps1"
   ```

2. **Actualiza la línea 8**:
   ```powershell
   # Cambiar de:
   $WEBHOOK_URL = "https://tunnel.n8n.cloud/webhook/asistente-personal-tardigrado"
   
   # A (con tu URL real del tunnel):
   $WEBHOOK_URL = "https://xxxxxxx-xxxx-xxxx.tunnel.n8n.cloud/webhook/asistente-personal-tardigrado"
   ```

3. **Guarda y ejecuta el script**:
   ```powershell
   cd "c:\Users\Tardigrado\Desktop\TAVILGA\PLANTILLAS N8N"
   powershell -ExecutionPolicy Bypass -File configurar_webhook_telegram.ps1
   ```

---

### 3. Configurar Credenciales en n8n

Una vez importado el workflow, debes configurar las credenciales:

#### A. Telegram API (3 nodos)
- Nodos: `Obtener Audio de Telegram`, `Enviar Respuesta Telegram`
- Token ya configurado: `8454970710:AAH_-8wPX1a0YIUPeufNwm4h9Ynxx_LsZBk`
- En n8n: Crear credencial de tipo "Telegram API"
- Pegar el token

#### B. OpenAI API (solo para Whisper - audio)
- Nodo: `Transcribir audio`
- Necesitas una API key de OpenAI: https://platform.openai.com/api-keys
- En n8n: Crear credencial de tipo "OpenAI API"
- Pegar tu API key

#### C. OpenRouter API (Gemini - GRATIS)
- Nodo: `OpenRouter Chat Model`
- Regístrate en: https://openrouter.ai/
- Crea una API key: https://openrouter.ai/keys
- En n8n: Crear credencial de tipo "OpenAI" (sí, usa el mismo tipo)
- **Base URL**: `https://openrouter.ai/api/v1`
- **API Key**: Tu key de OpenRouter
- El modelo ya está configurado: `google/gemini-2.0-flash-exp:free`

#### D. Google Calendar OAuth2 (4 nodos)
- Email ya configurado: `subscribe.catalog@gmail.com`
- En n8n: Crear credencial de tipo "Google Calendar OAuth2 API"
- Seguir el asistente de OAuth2
- Autorizar acceso a Google Calendar

#### E. Gmail OAuth2 (3 nodos)
- En n8n: Crear credencial de tipo "Gmail OAuth2 API"
- Seguir el asistente de OAuth2
- Autorizar acceso a Gmail

---

### 4. Google Tasks (Opcional - para más adelante)

**Actualmente no configurado** porque no tienes lista de Tasks.

**Para configurarlo en el futuro**:

1. **Crear o encontrar tu lista de Tasks**:
   - Ve a https://tasks.google.com
   - Crea una lista o usa "My Tasks"

2. **Obtener el ID de la lista**:
   - En n8n, crea un nodo temporal "Google Tasks"
   - Operación: "Get All Lists"
   - Ejecuta el nodo
   - Copia el ID de tu lista

3. **Actualizar los 4 nodos de Tasks**:
   - Buscar: `YOUR_GOOGLE_TASKS_LIST_ID`
   - Reemplazar con tu ID real

4. **Actualizar System Prompt**:
   - Añadir de nuevo la sección de Google Tasks en el prompt del AI Agent

---

## 🧪 Pruebas a Realizar

Una vez todo configurado y el workflow activado:

### Prueba 1: Mensaje de Texto Básico
```
Tú: "Hola, ¿qué puedes hacer?"
Bot: Describe sus capacidades
```

### Prueba 2: Crear Evento en Calendar
```
Tú: "Crea un evento mañana a las 10am: Reunión con equipo"
Bot: Confirma creación del evento
```

### Prueba 3: Consultar Calendario
```
Tú: "¿Qué eventos tengo esta semana?"
Bot: Lista los eventos
```

### Prueba 4: Enviar Email
```
Tú: "Envía un email a test@example.com con asunto: Prueba"
Bot: Confirma envío
```

### Prueba 5: Audio (si configuraste OpenAI)
- Envía un mensaje de voz
- El bot debería transcribirlo y responder

---

## 📊 Resumen de Herramientas Disponibles

| Herramienta | Status | Descripción |
|-------------|--------|-------------|
| **Email (Gmail)** | ✅ Listo | 3 herramientas: enviar, comprobar, etiquetar |
| **Calendar (Google)** | ✅ Listo | 4 herramientas: crear, eliminar, actualizar, consultar |
| **Tasks (Google)** | ⏸️ Pendiente | 4 herramientas deshabilitadas hasta configurar lista |
| **Audio (Whisper)** | ⏸️ Pendiente | Requiere API key de OpenAI |
| **Memoria** | ✅ Listo | Conversacional por chat_id |
| **AI (Gemini)** | ✅ Listo | Modelo gratuito via OpenRouter |

---

## 💰 Costes Estimados

- **Gemini 2.0 Flash (OpenRouter)**: $0/mes ✅ GRATIS
- **Whisper (OpenAI)**: ~$0.006/min de audio (~$0.30 por 50 min) 
- **Google APIs**: $0 (versión gratuita)
- **Telegram**: $0
- **n8n**: Depende de tu plan/instalación

**Total mensual**: < $5 (y solo si usas mucho audio)

---

## 🆘 Si Algo Falla

1. **Webhook no responde**:
   - Verifica que n8n esté corriendo
   - Verifica que el tunnel esté activo
   - Ejecuta el script de webhook de nuevo
   - Verifica con: `curl "https://api.telegram.org/bot8454970710:AAH_-8wPX1a0YIUPeufNwm4h9Ynxx_LsZBk/getWebhookInfo"`

2. **Credenciales inválidas**:
   - Reconfigura las credenciales OAuth2 en n8n
   - Asegúrate de autorizar todos los permisos

3. **Email de Calendar no funciona**:
   - Verifica que sea el email correcto: `subscribe.catalog@gmail.com`
   - Asegúrate de haber autorizado Google Calendar OAuth2

---

**¡Todo listo una vez sigas estos pasos! 🚀**

*Las configuraciones iniciales del workflow ya están hechas, solo falta iniciar n8n y configurar las credenciales.*
