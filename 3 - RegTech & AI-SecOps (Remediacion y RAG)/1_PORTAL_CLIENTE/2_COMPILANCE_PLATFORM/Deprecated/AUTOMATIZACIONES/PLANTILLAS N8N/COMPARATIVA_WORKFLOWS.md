# 📊 Comparativa de Workflows n8n para Telegram Bot

## Archivos Disponibles

### 1. `Agente_Secretario - TARDIGRADO.json` (Original)
**Descripción**: Workflow original con Telegram Trigger (requiere polling)

**Características**:
- ❌ **Problema**: Requiere HTTPS para webhook
- ✅ Soporta texto y audio
- ✅ 4 herramientas de Google Calendar
- ✅ Memoria conversacional
- ✅ OpenAI GPT-4o-mini
- ❌ Sin herramientas de Email
- ❌ Sin herramientas de Tasks

**Solución de webhook**: Activar tunnel de n8n

---

### 2. `Agente_Secretario - TARDIGRADO - ENHANCED.json` (Mejorado)
**Descripción**: Versión mejorada con todas las herramientas MCP integradas y Telegram Trigger con soporte HTTPS

**Características**:
- ✅ **12 herramientas AI totales**
- ✅ Telegram Trigger (se activa automáticamente)
- ✅ 3 herramientas Gmail (enviar, comprobar, etiquetar)
- ✅ 4 herramientas Google Tasks (crear, listar, completar, eliminar)
- ✅ 4 herramientas Google Calendar (crear, eliminar, actualizar, consultar)
- ✅ OpenAI GPT-4o-mini
- ✅ Memoria conversacional
- ✅ Transcripción de audio con Whisper
- ✅ System prompt detallado con todas las capacidades

**Ventajas**:
- Configuración más sencilla (no requiere registrar webhook manualmente)
- Todas las herramientas de productividad integradas
- System prompt mejorado

**Desventajas**:
- Requiere tunnel de n8n activo para HTTPS
- Usa tokens de OpenAI (costes variables según uso)

---

### 3. `Asistente Personal_webhook.json` (Original del usuario)
**Descripción**: Workflow con Webhook manual y Gemini 2.0 Flash gratuito

**Características**:
- ✅ Webhook HTTPS configurado
- ✅ Gemini 2.0 Flash **GRATUITO** (OpenRouter)
- ✅ 4 herramientas de Google Calendar
- ✅ Soporta texto y audio
- ✅ Memoria conversacional
- ❌ Email placeholder sin configurar
- ❌ Sin herramientas de Email
- ❌ Sin herramientas de Tasks
- ❌ Nodo "Get a chat" innecesario

**Ventajas**:
- Modelo AI completamente gratuito
- Webhook ya configurado

**Desventajas**:
- Requiere registro manual del webhook en Telegram
- Funcionalidad limitada (solo Calendar)

---

### 4. `Asistente_Personal_OPTIMIZADO.json` (Nuevo - Recomendado)
**Descripción**: Versión optimizada con webhook, Gemini gratuito, y todas las herramientas integradas

**Características**:
- ✅ **12 herramientas AI totales**
- ✅ Webhook HTTPS
- ✅ Gemini 2.0 Flash **GRATUITO** (OpenRouter)
- ✅ 3 herramientas Gmail (enviar, comprobar, etiquetar)
- ✅ 4 herramientas Google Tasks (crear, listar, completar, eliminar)
- ✅ 4 herramientas Google Calendar (crear, eliminar, actualizar, consultar)
- ✅ Memoria conversacional
- ✅ Transcripción de audio con Whisper (OpenAI)
- ✅ System prompt detallado
- ✅ Arquitectura limpia optimizada

**Ventajas**:
- **Modelo AI completamente GRATUITO** (Gemini 2.0 Flash)
- Todas las herramientas de productividad
- Sin costes recurrentes (excepto Whisper para audio)
- Arquitectura más limpia

**Desventajas**:
- Requiere registro manual del webhook en Telegram
- Configuración inicial de credenciales más compleja (5 tipos)

---

## 📊 Tabla Comparativa Completa

| Característica | Original | Enhanced | User Webhook | **Optimizado** |
|----------------|----------|----------|--------------|----------------|
| **Trigger** | Telegram Trigger | Telegram Trigger | Webhook | **Webhook** |
| **HTTPS** | Tunnel requerido | Tunnel requerido | ✅ Soportado | ✅ **Soportado** |
| **Modelo AI** | GPT-4o-mini | GPT-4o-mini | Gemini 2.0 Flash | **Gemini 2.0 Flash** |
| **Coste AI** | $$ (OpenAI) | $$ (OpenAI) | ✅ **GRATIS** | ✅ **GRATIS** |
| **Herramientas totales** | 4 | **12** | 4 | **12** |
| **Email (Gmail)** | ❌ | ✅ 3 | ❌ | ✅ **3** |
| **Tasks (Google)** | ❌ | ✅ 4 | ❌ | ✅ **4** |
| **Calendar (Google)** | ✅ 4 | ✅ 4 | ✅ 4 | ✅ **4** |
| **Audio transcription** | ✅ Whisper | ✅ Whisper | ✅ Whisper | ✅ **Whisper** |
| **Memoria conversacional** | ✅ | ✅ | ✅ | ✅ |
| **System Prompt** | Básico | Detallado | Básico | **Detallado** |
| **Configuración** | Media | Media | Manual | **Manual** |
| **Arquitectura** | Limpia | Limpia | Con nodo extra | **Limpia** |
| **Recomendado para** | Pruebas rápidas | Uso profesional | Presupuesto $0 | **Uso profesional + $0** |

---

## 🎯 ¿Cuál Usar?

### ⚡ Para pruebas rápidas:
**`Agente_Secretario - TARDIGRADO.json`** (Original)
- Fácil de configurar
- Solo activa el tunnel de n8n
- Funcionalidad básica

### 💼 Para uso profesional con presupuesto:
**`Agente_Secretario - TARDIGRADO - ENHANCED.json`** (Enhanced)
- Máxima funcionalidad
- GPT-4o-mini (mayor calidad)
- Configuración automática de webhook

### 💰 Para presupuesto cero (RECOMENDADO):
**`Asistente_Personal_OPTIMIZADO.json`** ⭐
- **Modelo AI GRATIS** (Gemini 2.0 Flash)
- **12 herramientas** de productividad
- Calidad similar a GPT-4o-mini
- Solo pagas Whisper para transcripción de audio (~$0.006/minuto)

---

## 💡 Recomendación Final

### 🏆 MEJOR OPCIÓN: `Asistente_Personal_OPTIMIZADO.json`

**Razones**:
1. ✅ **Coste $0** para el modelo AI principal
2. ✅ **12 herramientas** completas (Email, Tasks, Calendar)
3. ✅ **Gemini 2.0 Flash** es muy potente y rápido
4. ✅ **Arquitectura optimizada** y limpia
5. ✅ **System prompt mejorado** con todas las capacidades

**Costes estimados**:
- **Gemini 2.0 Flash (OpenRouter)**: $0/mes 🎉
- **Whisper (audio)**: ~$0.006/min (~$0.30 por 50 minutos)
- **Google APIs**: $0 (versión gratuita)
- **n8n**: Depende de tu plan

**Total mensual estimado**: < $5 (solo si usas mucho audio)

---

## 📋 Archivos de Ayuda Incluidos

| Archivo | Descripción |
|---------|-------------|
| `GUIA_CONFIGURACION_AGENTE_TARDIGRADO.md` | Guía para Enhanced (Telegram Trigger) |
| `GUIA_ASISTENTE_OPTIMIZADO.md` | **Guía completa para Optimizado (Webhook)** ⭐ |
| `QUICK_START.md` | Referencia rápida |
| `configurar_webhook_telegram.ps1` | **Script para registrar webhook automáticamente** ⭐ |

---

## 🚀 Guía de Implementación Rápida

### Para `Asistente_Personal_OPTIMIZADO.json`:

1. **Activar tunnel de n8n**:
   ```
   Settings > n8n API > Enable Tunnel
   ```

2. **Configurar credenciales** (5 tipos):
   - Telegram Bot API
   - OpenAI API (solo para Whisper)
   - OpenRouter API (Gemini - GRATIS)
   - Google Calendar OAuth2
   - Gmail OAuth2
   - Google Tasks OAuth2

3. **Ejecutar script de webhook**:
   ```powershell
   # Editar configurar_webhook_telegram.ps1 con tus valores
   # Actualizar TELEGRAM_BOT_TOKEN y WEBHOOK_URL
   .\configurar_webhook_telegram.ps1
   ```

4. **Importar workflow** en n8n

5. **Activar y probar**

---

**¡Listo para usar! 🎉**

*Creado por: Tardigrado | Powered by n8n + Gemini 2.0 Flash*
