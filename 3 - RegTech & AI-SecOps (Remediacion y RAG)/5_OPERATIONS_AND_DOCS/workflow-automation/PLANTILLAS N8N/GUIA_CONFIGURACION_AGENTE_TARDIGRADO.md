# 🚀 Guía de Configuración - Agente Secretario TARDIGRADO

## 📋 Resumen del Workflow

Has recibido un workflow n8n mejorado que integra:
- ✅ **12 herramientas AI** conectadas al agente
- ✅ **Webhook HTTPS** mediante tunnel de n8n
- ✅ **Gestión de Email** (Gmail)
- ✅ **Gestión de Tareas** (Google Tasks)
- ✅ **Gestión de Calendario** (Google Calendar)
- ✅ **Transcripción de audio** con Whisper
- ✅ **Memoria conversacional** por usuario

---

## 🔧 Paso 1: Activar el Tunnel de n8n (HTTPS)

> [!IMPORTANT]
> **Este es el paso crítico** para resolver el error: "Bad Request: bad webhook: An HTTPS URL must be provided for webhook"

### Instrucciones:

1. **Abre tu instancia de n8n** en el navegador
2. **Ve a Settings** (⚙️ en el menú lateral)
3. **Haz clic en "n8n API"**
4. **Activa "Production webhook URL"** o **"Tunnel"**
   - Aparecerá una URL HTTPS como: `https://xxxxx.tunnel.n8n.cloud`
5. **Copia esta URL** (la necesitarás para verificar)

### ¿Por qué es necesario?

Telegram **requiere HTTPS** para los webhooks. El tunnel de n8n crea un proxy HTTPS seguro hacia tu instancia de n8n, incluso si está corriendo en HTTP localmente (localhost:5678).

---

## 📥 Paso 2: Importar el Workflow Mejorado

1. **Abre n8n**
2. **Haz clic en "+" > "Import from file"**
3. **Selecciona el archivo**: `Agente_Secretario - TARDIGRADO - ENHANCED.json`
4. **Importa el workflow**

---

## 🔑 Paso 3: Configurar Credenciales

El workflow necesita **5 tipos de credenciales**. Debes configurar cada una:

### 3.1 Telegram Bot API

1. **Ve al nodo "Telegram Trigger"**
2. **Haz clic en "Credential to connect with"**
3. **Selecciona tu credencial de Telegram** o crea una nueva:
   - **Token**: El token de tu bot de Telegram (obtenerlo de @BotFather)
   - **Base URL**: Dejar por defecto

### 3.2 OpenAI API

Necesaria para el modelo de chat y transcripción de audio.

1. **Nodos que usan esta credencial**:
   - "OpenAI Chat Model"
   - "Transcribir audio"
2. **Configuración**:
   - **API Key**: Tu API key de OpenAI (https://platform.openai.com/api-keys)

### 3.3 Google Calendar OAuth2

1. **Nodos que usan esta credencial**:
   - "Calendar - Crear evento"
   - "Calendar - Eliminar evento"
   - "Calendar - Actualizar evento"
   - "Calendar - Comprobar disponibilidad"
2. **Configuración**:
   - Sigue el asistente de OAuth2 de n8n
   - Autoriza el acceso a Google Calendar
   - **Importante**: Actualiza el valor del calendario en cada nodo (actualmente: `subscribe.catalog@gmail.com`)

### 3.4 Gmail OAuth2

1. **Nodos que usan esta credencial**:
   - "Gmail - Enviar email"
   - "Gmail - Comprobar emails"
   - "Gmail - Añadir etiqueta"
2. **Configuración**:
   - Sigue el asistente de OAuth2 de n8n
   - Autoriza el acceso a Gmail

### 3.5 Google Tasks OAuth2

1. **Nodos que usan esta credencial**:
   - "Tasks - Crear tarea"
   - "Tasks - Comprobar tareas pendientes"
   - "Tasks - Completar tarea"
   - "Tasks - Eliminar tarea"
2. **Configuración**:
   - Sigue el asistente de OAuth2 de n8n
   - Autoriza el acceso a Google Tasks
   - **Importante**: Después de conectar, obtén el ID de tu lista de tareas:
     - Ve a Google Tasks en web
     - El ID está en la URL o usa el nodo de n8n para listar todas las listas
     - Reemplaza `YOUR_GOOGLE_TASKS_LIST_ID` en cada nodo de Tasks con tu ID real

---

## ⚙️ Paso 4: Configurar el Calendario y Lista de Tareas

### Google Calendar:

En los 4 nodos de Calendar, actualiza el campo `calendar` con tu calendario:
- Valor actual: `subscribe.catalog@gmail.com`
- **Cámbialo por**: Tu email de Google Calendar

### Google Tasks:

En los 4 nodos de Tasks, actualiza el campo `task` con tu lista de tareas:
- Valor actual: `YOUR_GOOGLE_TASKS_LIST_ID`
- **Cómo obtener el ID**:
  1. Conéctate a Google Tasks OAuth2
  2. Usa un nodo temporal "Google Tasks" con operación "Get All Lists"
  3. Ejecuta el nodo para ver tus listas
  4. Copia el ID de la lista que quieras usar
  5. Pégalo en todos los nodos de Tasks

---

## ✅ Paso 5: Activar el Workflow

1. **Revisa que todas las credenciales estén configuradas** (sin errores rojos)
2. **Haz clic en "Active" (toggle en la esquina superior derecha)**
3. **Verifica el estado del webhook**:
   - Si todo está correcto, n8n mostrará "Listening for webhook calls"
   - Si hay error, revisa que el tunnel esté activo

---

## 🧪 Paso 6: Probar el Bot

### Prueba básica de texto:

1. **Abre Telegram**
2. **Busca tu bot** (el que creaste con @BotFather)
3. **Envía un mensaje**: "Hola, ¿qué puedes hacer?"
4. **El bot debería responder** describiendo sus capacidades

### Pruebas de cada herramienta:

#### 📧 Email:
```
"Envía un email a test@example.com con asunto: Prueba y mensaje: Esto es una prueba"
```

```
"¿Tengo emails sin leer de hoy?"
```

#### ✅ Tareas:
```
"Crea una tarea llamada: Revisar documentos"
```

```
"¿Qué tareas tengo pendientes?"
```

```
"Marca como completada la tarea Revisar documentos"
```

#### 📅 Calendario:
```
"Crea un evento mañana a las 10am llamado: Reunión con el equipo"
```

```
"¿Qué eventos tengo esta semana?"
```

#### 🎤 Audio:
- **Envía un mensaje de voz** a tu bot
- El bot debería transcribir el audio y responder

---

## 🔍 Verificación y Debugging

### Verificar que el webhook HTTPS funciona:

1. **En n8n, ve al workflow activo**
2. **Mira la esquina superior donde dice "Listening for webhook"**
3. **Debería mostrar**: `https://xxxxx.tunnel.n8n.cloud/webhook/telegram-webhook-secretario-enhanced`

### Si el bot no responde:

1. **Revisa los logs de ejecución** en n8n (pestaña "Executions")
2. **Verifica que todas las credenciales estén configuradas**
3. **Comprueba que el tunnel de n8n esté activo**
4. **Revisa que el bot esté activo** (toggle "Active" en ON)

### Errores comunes:

| Error | Solución |
|-------|----------|
| "Bad webhook: HTTPS required" | Activa el tunnel de n8n en Settings > n8n API |
| "Invalid credentials" | Reconfigura las credenciales OAuth2 de Google |
| "Calendar/Task not found" | Actualiza el ID del calendario o lista de tareas |
| "OpenAI API error" | Verifica tu API key de OpenAI y que tengas créditos |

---

## 📊 Capacidades del Agente

El agente puede realizar las siguientes acciones:

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

## 💡 Uso Avanzado

### Personalizar el System Prompt:

1. **Ve al nodo "AI Agent"**
2. **Edita el campo "System Message"**
3. **Personaliza** el comportamiento, tono y capacidades del agente

### Añadir más herramientas:

1. **Arrastra un nuevo nodo Tool** al canvas
2. **Conéctalo al nodo "AI Agent"** mediante la conexión `ai_tool`
3. **El agente automáticamente tendrá acceso** a la nueva herramienta

### Cambiar el modelo de IA:

1. **Ve al nodo "OpenAI Chat Model"**
2. **En el campo "Model"**, selecciona otro modelo:
   - `gpt-4o`: Más inteligente, más caro
   - `gpt-4o-mini`: Balance precio/calidad (recomendado)
   - `gpt-3.5-turbo`: Más rápido, más barato

---

## 🛡️ Seguridad y Mejores Prácticas

> [!WARNING]
> **Credenciales**: Nunca compartas tu workflow con las credenciales incluidas. Exporta siempre sin credenciales.

> [!TIP]
> **Tunnel gratuito**: El tunnel de n8n es gratuito, pero se desactiva si no lo usas. Reactívalo cuando sea necesario.

> [!CAUTION]
> **Costes de OpenAI**: El agente utiliza tokens de OpenAI. Monitorea tu uso en https://platform.openai.com/usage

---

## 📞 Soporte

Si tienes problemas:
1. Revisa los logs de ejecución en n8n
2. Verifica todas las configuraciones paso a paso
3. Comprueba que el tunnel HTTPS esté activo
4. Asegúrate de que las credenciales de Google estén autorizadas correctamente

---

**¡Disfruta de tu Agente Secretario Personal! 🚀**

*Creado por: Tardigrado | Powered by n8n + AI*
