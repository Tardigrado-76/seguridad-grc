# 🚀 Quick Start - Agente Secretario TARDIGRADO

## ⚡ En 5 Pasos

### 1️⃣ Activar HTTPS Tunnel
```
n8n > Settings > n8n API > Enable "Production webhook URL" o "Tunnel"
```
- Esto resolverá el error: "bad webhook: An HTTPS URL must be provided"

### 2️⃣ Importar Workflow
```
n8n > + > Import from file > Seleccionar:
"Agente_Secretario - TARDIGRADO - ENHANCED.json"
```

### 3️⃣ Configurar Credenciales (5 tipos)
- [ ] Telegram Bot API
- [ ] OpenAI API
- [ ] Google Calendar OAuth2
- [ ] Gmail OAuth2
- [ ] Google Tasks OAuth2

### 4️⃣ Actualizar IDs
- **Google Calendar**: Cambiar `subscribe.catalog@gmail.com` por tu email
- **Google Tasks**: Reemplazar `YOUR_GOOGLE_TASKS_LIST_ID` con tu lista

### 5️⃣ Activar y Probar
```
n8n > Toggle "Active" > ON
Telegram > Enviar mensaje a tu bot: "Hola, ¿qué puedes hacer?"
```

---

## 🎯 Capacidades del Bot

### 📧 Email (Gmail)
- ✅ Enviar emails
- ✅ Comprobar no leídos
- ✅ Añadir etiquetas

### ✅ Tareas (Google Tasks)
- ✅ Crear tareas
- ✅ Listar pendientes
- ✅ Completar tareas
- ✅ Eliminar tareas

### 📅 Calendario (Google Calendar)
- ✅ Crear eventos
- ✅ Consultar disponibilidad
- ✅ Actualizar eventos
- ✅ Eliminar eventos

### 🎤 Otros
- ✅ Transcribir audios
- ✅ Memoria conversacional

---

## 🧪 Pruebas Rápidas

```
"Crea un evento mañana a las 10am: Reunión con equipo"
"¿Qué eventos tengo esta semana?"
"Crea una tarea: Revisar documentos"
"¿Qué tareas tengo pendientes?"
"Envía un email a test@example.com con asunto: Prueba"
"¿Tengo emails sin leer?"
[Mensaje de voz] → El bot transcribe automáticamente
```

---

## 📚 Documentación Completa

Para instrucciones detalladas, consulta:
- **Guía de configuración**: `GUIA_CONFIGURACION_AGENTE_TARDIGRADO.md`
- **Walkthrough completo**: Artifact `walkthrough.md`

---

## 🆘 Problemas Comunes

| Problema | Solución |
|----------|----------|
| "Bad webhook: HTTPS required" | Activar tunnel en Settings > n8n API |
| Bot no responde | Verificar que el workflow esté "Active" |
| Error de credenciales | Reconfigurar OAuth2 en n8n |
| Calendar/Task not found | Actualizar IDs en los nodos |

---

**¡Listo para usar! 🎉**

*by Tardigrado | Powered by n8n*
