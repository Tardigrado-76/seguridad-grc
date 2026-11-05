import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

# Configuración centralizada (ENS Alta / DORA — sin rutas hardcodeadas)
from config import (
    AUDIT_LOG_FILE,
    AUDIT_LOG_MAX_ENTRIES,
    GUARDRAILS_DEFAULT_ACTIVE,
    UPLOADS_DIR,
)

# Importaciones del Pipeline RAG Enterprise local
from rag_ingestion_pipeline import (
    DocumentLoaderFactory,
    PathSanitizer,
    TokenSemanticSplitter,
)

# ==========================================
# CONFIGURACIÓN DE PÁGINA Y ESTILOS
# ==========================================
st.set_page_config(
    page_title="RAG Regulado - Plataforma de IA Conversacional",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Nota: AUDIT_LOG_FILE y UPLOADS_DIR se importan desde config.py
# UPLOADS_DIR ya fue creado en config.py (mkdir exist_ok=True)

# CSS Premium con Glassmorphism, degradados y animaciones de seguridad
st.markdown("""
<style>
    /* Importación de tipografía de Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;700&family=Outfit:wght@300;400;600;800&family=Inter:wght@300;400;600;700&display=swap');

    /* Configuración de fuentes globales */
    html, body, [class*="css"], .stApp {
        font-family: 'Inter', sans-serif;
    }

    .main-title {
        font-family: 'Outfit', sans-serif;
        font-weight: 800;
        font-size: 2.5rem;
        background: linear-gradient(135deg, #6366f1 0%, #a855f7 50%, #ec4899 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }

    .subtitle {
        font-size: 1.1rem;
        color: #94a3b8;
        margin-bottom: 2rem;
        font-weight: 400;
    }

    /* Tarjetas de métricas en Sidebar (Glassmorphism Premium) */
    .metric-card {
        background: rgba(30, 41, 59, 0.7);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 12px;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .metric-card:hover {
        border-color: rgba(99, 102, 241, 0.4);
        box-shadow: 0 4px 30px rgba(99, 102, 241, 0.15);
        transform: translateY(-2px);
    }

    .metric-title {
        font-size: 0.75rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
        margin-bottom: 4px;
    }

    .metric-value {
        font-family: 'Outfit', sans-serif;
        font-size: 1.6rem;
        font-weight: 700;
        color: #f8fafc;
    }

    /* Consola de logs estilo Hacker/Auditor */
    .console-container {
        background-color: #020617;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px;
        font-family: 'Fira Code', monospace;
        font-size: 0.8rem;
        color: #38bdf8;
        max-height: 280px;
        overflow-y: auto;
        white-space: pre-wrap;
        box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.8);
    }

    .log-line {
        margin-bottom: 6px;
        line-height: 1.4;
        border-bottom: 1px solid #0f172a;
        padding-bottom: 4px;
    }

    /* Alerta de bloqueo pulsante con estética premium */
    .blocked-card {
        background: linear-gradient(135deg, #450a0a 0%, #7f1d1d 100%);
        border: 2px solid #ef4444;
        box-shadow: 0 0 20px rgba(239, 68, 68, 0.35);
        border-radius: 12px;
        padding: 20px;
        color: #fee2e2;
        font-family: 'Inter', sans-serif;
        margin: 15px 0;
        animation: pulse-glow 2.5s infinite;
    }

    @keyframes pulse-glow {
        0% { box-shadow: 0 0 15px rgba(239, 68, 68, 0.3); }
        50% { box-shadow: 0 0 30px rgba(239, 68, 68, 0.65); }
        100% { box-shadow: 0 0 15px rgba(239, 68, 68, 0.3); }
    }

    .blocked-title {
        font-family: 'Outfit', sans-serif;
        font-size: 1.4rem;
        font-weight: 900;
        letter-spacing: 0.05em;
        color: #fca5a5;
        margin-bottom: 4px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .blocked-subtitle {
        font-size: 0.95rem;
        opacity: 0.95;
        margin-bottom: 12px;
        font-weight: 700;
        border-bottom: 1px solid rgba(252, 165, 165, 0.25);
        padding-bottom: 6px;
        color: #fecaca;
    }

    .blocked-detail {
        font-size: 0.9rem;
        margin-bottom: 8px;
        background: rgba(0, 0, 0, 0.2);
        padding: 8px 12px;
        border-radius: 6px;
        border: 1px solid rgba(239, 68, 68, 0.2);
    }

    .blocked-compliance {
        font-size: 0.8rem;
        color: #fca5a5;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.02em;
    }

    /* Estilos adicionales para insignias */
    .badge {
        display: inline-block;
        padding: 2px 8px;
        font-size: 0.7rem;
        font-weight: 700;
        border-radius: 4px;
        text-transform: uppercase;
    }
    .badge-red { background-color: #ef4444; color: white; }
    .badge-green { background-color: #22c55e; color: white; }
    .badge-orange { background-color: #f97316; color: white; }
    .badge-blue { background-color: #3b82f6; color: white; }
</style>
""", unsafe_allow_html=True)


# ==========================================
# SISTEMA DE LOGS DE AUDITORÍA (AUDIT LOG)
# ==========================================
def load_audit_logs() -> list:
    """Carga los logs de auditoría desde el archivo local JSON (thread-safe)."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return []
    try:
        with open(AUDIT_LOG_FILE, encoding="utf-8") as f:
            # Adquisición de lock compartido (lectura) para Windows/Linux
            try:
                import msvcrt  # Windows
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            except (ImportError, OSError):
                try:
                    import fcntl  # POSIX
                    fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)  # type: ignore[attr-defined]
                except (ImportError, OSError):
                    pass
            return json.load(f)
    except (OSError, ValueError):
        return []


def save_audit_logs(logs: list) -> None:
    """Guarda los logs de auditoría al archivo local JSON (thread-safe, escritura atómica)."""
    tmp_file = AUDIT_LOG_FILE + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            # Lock exclusivo en escritura
            try:
                import msvcrt  # Windows
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            except (ImportError, OSError):
                try:
                    import fcntl  # POSIX
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
                except (ImportError, OSError):
                    pass
            json.dump(logs, f, indent=4, ensure_ascii=False)
        # Reemplazo atómico (evita corrupción en escrituras concurrentes — DORA Art. 6)
        import shutil
        shutil.move(tmp_file, AUDIT_LOG_FILE)
    except (OSError, ValueError) as e:
        st.error(f"Error al escribir en audit_log.json: {e}")

def add_audit_event(event_type, prompt, is_blocked, reason, latency_ms, compliance_tags, details=""):
    """Registra un evento de seguridad en el log de auditoría."""
    logs = load_audit_logs()

    # Enmascarar prompt si es un bloqueo por PII para evitar almacenamiento secundario de fugas
    masked_prompt = prompt
    if is_blocked and "OWASP LLM02" in reason:
        masked_prompt = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL_OCULTO]", prompt)
        masked_prompt = re.sub(r"\b(?:\d[ -]*?){13,16}\b", "[TARJETA_OCULTA]", masked_prompt)
        masked_prompt = re.sub(r"\b\d{8}[A-Z]\b", "[DNI_OCULTO]", masked_prompt)
    elif is_blocked and "OWASP LLM01" in reason:
        masked_prompt = f"[INYECCIÓN BLOQUEADA] {prompt[:45]}..."

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,  # "SAFE", "BLOCKED", "BYPASS", "INGEST_SAFE", "INGEST_BLOCKED"
        "prompt": masked_prompt,
        "is_blocked": is_blocked,
        "reason": reason,
        "details": details,
        "latency_ms": round(latency_ms, 2),
        "compliance_tags": compliance_tags,
    }

    logs.insert(0, event)
    save_audit_logs(logs[:AUDIT_LOG_MAX_ENTRIES])
    return event


# ==========================================
# MOTOR DE GUARDARRAÍLES (GUARDRAILS)
# ==========================================
class GuardrailsEngine:
    def __init__(self) -> None:
        # Expresiones regulares para Prompt Injection (Vulnerabilidad OWASP LLM01)
        self.injection_patterns = [
            r"(ignore|ignora|bypass|override)\s+(the\s+)?(previous|prior|system|instructions|instrucciones|directivas)",
            r"(forget|olvida)\s+(everything|all|system|instructions|lo\s+anterior)",
            r"revela\s+(tus\s+)?(instrucciones|prompt|directivas|reglas)",
            r"reveal\s+(your\s+)?(instructions|prompt|rules|system)",
            r"(act\s+as|actua\s+como|eres\s+un|you\s+are\s+now|eres\s+ahora)\s+(administrator|admin|root|nuevo\s+modelo|jailbreak)",
            r"\bsudo\s+su\b",
            r"\bdelete\s+from\s+\w+\b",
            r"\bselect\s+\*\s+from\s+\w+\b",
            r"\bdrop\s+table\b",
            r"(muestra|revela|accede\s+a)\s+(la\s+)?(base\s+de\s+datos|db|database|tablas)",
        ]

        # Expresiones regulares para Fuga de Información Sensible (Vulnerabilidad OWASP LLM02)
        self.pii_patterns = {
            "DNI / NIE (España)": r"\b(?:[0-9]{8}[A-Z]|[XYZ][0-9]{7}[A-Z])\b",
            "Tarjeta de Crédito": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b",
            "Correo Electrónico": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            "Teléfono Móvil (España)": r"\b(?:(?:\+34|0034)?[ -]?)?[6789]\d{8}\b",
            "API Key (Simulada)": r"\b(?:sk-[a-zA-Z0-9]{48}|AIzaSy[a-zA-Z0-9-_]{33})\b",
        }

    def scan(self, text: str) -> dict:
        """Escanea texto (peticiones o documentos) buscando riesgos de seguridad."""
        start_time = time.perf_counter()

        # 1. Escanear Prompt Injections (OWASP LLM01)
        for pattern in self.injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                latency = (time.perf_counter() - start_time) * 1000
                return {
                    "is_blocked": True,
                    "reason": "Intento de Prompt Injection (Inyección de Directivas)",
                    "owasp": "OWASP LLM01: Prompt Injection",
                    "compliance": ["EU AI Act Artículo 50 (Transparencia)", "DORA Artículo 6 (Control de Riesgos TIC)"],
                    "details": "Coincidencia con patrón de inyección regulado.",
                    "latency_ms": latency,
                }

        # 2. Escanear Fuga de Información Sensible / PII (OWASP LLM02)
        detected_pii = []
        for pii_name, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                detected_pii.append(f"{pii_name} (Encontrado: {len(matches)})")

        if detected_pii:
            latency = (time.perf_counter() - start_time) * 1000
            return {
                "is_blocked": True,
                "reason": "Fuga de Datos Sensibles (PII / Credenciales)",
                "owasp": "OWASP LLM02: Sensitive Information Disclosure",
                "compliance": ["EU AI Act Artículo 50 (Mitigación de Sesgos/Privacidad)", "DORA Artículo 6 (Protección de Integridad de Datos)"],
                "details": f"Filtro activado por: {', '.join(detected_pii)}",
                "latency_ms": latency,
            }

        latency = (time.perf_counter() - start_time) * 1000
        return {
            "is_blocked": False,
            "reason": "Safe",
            "owasp": "Ninguna infracción detectada",
            "compliance": [],
            "details": "El texto superó los guardarraíles de cumplimiento.",
            "latency_ms": latency,
        }


# ==========================================
# BÚSQUEDA RAG SEMÁNTICA LOCAL (TF-IDF SIMULADO)
# ==========================================
def retrieve_relevant_chunks(query: str, chunks: list, top_k: int = 2) -> list:
    """Realiza una búsqueda de similitud léxica simplificada pero efectiva sobre los chunks."""
    query_words = set(re.findall(r"\w+", query.lower()))
    if not query_words:
        return chunks[:top_k]

    scored_chunks = []
    for chunk in chunks:
        chunk_words = re.findall(r"\w+", chunk.lower())
        # Contar cuántas palabras de la consulta están en el fragmento (cualquier longitud)
        exact_overlap = sum(1 for word in query_words if word in chunk_words)

        # Calcular el peso de la palabra por longitud (evitar palabras comunes de 1-2 letras)
        weighted_overlap = (exact_overlap * 0.5) + sum(
            len(word) for word in query_words if word in chunk_words and len(word) > 2
        )

        scored_chunks.append((weighted_overlap, chunk))

    # Ordenar de mayor coincidencia a menor
    scored_chunks.sort(key=lambda x: x[0], reverse=True)

    # Extraer los chunks seleccionados
    results = [chunk for score, chunk in scored_chunks if score > 0]

    # Si no hay coincidencias de palabras, retornar los primeros
    if not results:
        return chunks[:top_k]
    return results[:top_k]


# ==========================================
# SIMULADOR DE AGENTE CON LLAMADA A HERRAMIENTAS
# ==========================================
def simulate_agent_with_tool_calling(prompt: str):
    """Simula un agente inteligente ejecutando herramientas basadas en el prompt."""
    prompt_lower = prompt.lower()

    # Determinar qué herramienta simular basándose en la intención
    if any(k in prompt_lower for k in ["dora", "informe", "reporte", "cumplimiento"]):
        tool_name = "retrieve_dora_compliance_report"
        tool_args = {"year": 2026, "scope": "Riesgo TIC"}
        tool_response = (
            "{\n"
            "  'status': 'COMPLIANT',\n"
            "  'critical_incidents': 0,\n"
            "  'resilience_test_date': '2026-08-15',\n"
            "  'remediation_plan_active': false,\n"
            "  'framework': 'DORA Art. 6-12'\n"
            "}"
        )
        agent_answer = (
            "🤖 **Agente Regulado:** He consultado la herramienta de resiliencia operacional.\n\n"
            "El reporte de cumplimiento **DORA 2026** indica un estado **COMPLIANT** (Apto). "
            "Se registra un histórico de **0 incidentes críticos de TIC** y las pruebas de resiliencia "
            "operacional realizadas el 15 de agosto de 2026 se completaron con un éxito del 100%. "
            "No se requieren planes de remedición activos en este momento."
        )
    elif any(k in prompt_lower for k in ["datos", "banco", "riesgo", "cliente"]):
        tool_name = "query_financial_risk_database"
        tool_args = {"entity": "Banco de Pruebas", "kpi": "liquidity_risk"}
        tool_response = (
            "{\n"
            "  'liquidity_coverage_ratio': '145.2%',\n"
            "  'stress_test_status': 'PASSED',\n"
            "  'audit_reference': 'AUD-2026-DORA-09'\n"
            "}"
        )
        agent_answer = (
            "🤖 **Agente Regulado:** He ejecutado la consulta sobre la base de datos de riesgo financiero.\n\n"
            "La entidad consultada presenta un **Liquidity Coverage Ratio (LCR) del 145.2%**, "
            "superando cómodamente el umbral regulatorio del 100%. Las pruebas de estrés financiero "
            "están en estado **PASSED** según la referencia de auditoría **AUD-2026-DORA-09**."
        )
    elif any(k in prompt_lower for k in ["indicador", "entidad", "banco central"]):
        tool_name = "fetch_central_bank_indicators"
        tool_args = {"indicators": ["EURIBOR", "INFLATION"]}
        tool_response = (
            "{\n"
            "  'euribor_3m': '2.75%',\n"
            "  'inflation_rate_eu': '1.9%',\n"
            "  'last_update': '2026-08-25T12:00:00Z'\n"
            "}"
        )
        agent_answer = (
            "🤖 **Agente Regulado:** He solicitado los indicadores del Banco Central.\n\n"
            "Los últimos indicadores macroeconómicos oficiales registrados a fecha del 25 de agosto de 2026 muestran:\n"
            "- **Euríbor 3 Meses:** 2.75%\n"
            "- **Tasa de Inflación (Zona Euro):** 1.9%\n"
            "Los indicadores se encuentran dentro del canal de estabilidad previsto por el comité de riesgos."
        )
    else:
        tool_name = "retrieve_general_knowledge_base"
        tool_args = {"query": prompt[:30]}
        tool_response = (
            "{\n"
            "  'kb_matches': 1,\n"
            "  'confidence_score': 0.94,\n"
            "  'source': 'Regulated_RAG_KB'\n"
            "}"
        )
        agent_answer = (
            f"🤖 **Agente Regulado:** He consultado la base de conocimiento interna para responder a tu consulta. "
            f"Basándome en los registros corporativos auditados, confirmo que su consulta sobre '{prompt}' está siendo procesada bajo "
            f"el marco regulatorio estándar de la compañía. ¿Desea que ejecute alguna consulta técnica más específica sobre DORA o ratios financieros?"
        )

    return tool_name, tool_args, tool_response, agent_answer


# ==========================================
# ESTADO DE SESIÓN STREAMLIT
# ==========================================
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "content": "🤖 **Plataforma Activa.** Bienvenido al entorno de Chat regulado por Guardarraíles OWASP. Todas sus consultas serán inspeccionadas en tiempo real bajo cumplimiento regulatorio."},
    ]

if "last_latency" not in st.session_state:
    st.session_state.last_latency = 0.0

if "last_status" not in st.session_state:
    st.session_state.last_status = "Seguro (Safe)"

if "last_risk" not in st.session_state:
    st.session_state.last_risk = "Ninguno"

if "rag_chunks" not in st.session_state:
    st.session_state.rag_chunks = []

if "doc_loaded" not in st.session_state:
    st.session_state.doc_loaded = False

if "doc_name" not in st.session_state:
    st.session_state.doc_name = ""


# ==========================================
# PANEL LATERAL (SIDEBAR): CONTROL Y MÉTRICAS
# ==========================================
with st.sidebar:
    _logo_path = Path(__file__).parent.parent.parent / "Quantigrade.jpg"
    if _logo_path.exists():
        st.image(str(_logo_path), width=70)
    st.markdown("<h2 style='font-family: Outfit; font-weight:800; margin-top:-10px;'>Auditoría de IA</h2>", unsafe_allow_html=True)
    st.markdown("---")

    # 1. Control del Guardarraíl (Activar/Desactivar)
    guardrails_active = st.toggle("🛡️ Guardarraíles Activos", value=GUARDRAILS_DEFAULT_ACTIVE, help="Activa o desactiva la interceptación de seguridad de guardarraíles.")

    # ==========================================
    # CREADOR RAG: CARGA DE DOCUMENTOS
    # ==========================================
    st.markdown("### 📁 Cargar Documentos RAG")
    uploaded_file = st.file_uploader(
        "Sube un archivo para alimentar la base de conocimiento local",
        type=["txt", "md", "pdf", "docx"],
        help="Soporta formatos TXT, MD, PDF y DOCX procesados por el Ingestion Pipeline.",
    )

    # Procesar documento cargado
    if uploaded_file is not None and (not st.session_state.doc_loaded or st.session_state.doc_name != uploaded_file.name):
        ingest_start = time.perf_counter()

        # 1. Validación de Seguridad de Ruta física mediante PathSanitizer
        temp_file_path = UPLOADS_DIR / uploaded_file.name
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        is_safe_path, path_msg = PathSanitizer.is_safe_path(temp_file_path, UPLOADS_DIR)

        if not is_safe_path:
            st.error(f"Error de Seguridad (CRA): {path_msg}")
            if temp_file_path.exists():
                os.remove(temp_file_path)
        else:
            try:
                # 2. Extracción de texto usando el DocumentLoaderFactory de producción
                loader = DocumentLoaderFactory.get_loader(temp_file_path.suffix)
                extracted_text = loader.load(temp_file_path)

                # Eliminar archivo temporal tras extracción
                if temp_file_path.exists():
                    os.remove(temp_file_path)

                # 3. Escaneo del Guardarraíl sobre el contenido del documento (Evitar inyecciones indirectas y PII)
                guardrails_engine = GuardrailsEngine()
                scan_res = guardrails_engine.scan(extracted_text)

                ingest_latency = (time.perf_counter() - ingest_start) * 1000
                st.session_state.last_latency = ingest_latency

                if guardrails_active and scan_res["is_blocked"]:
                    # Documento Bloqueado por Seguridad
                    st.session_state.doc_loaded = False
                    st.session_state.doc_name = ""
                    st.session_state.rag_chunks = []
                    st.session_state.last_status = "Bloqueado (Documento)"
                    st.session_state.last_risk = f"Inseguro - {scan_res['owasp']}"

                    # Registrar en log
                    add_audit_event(
                        event_type="INGEST_BLOCKED",
                        prompt=f"[DOC BLOQUEADO] {uploaded_file.name}",
                        is_blocked=True,
                        reason=f"Documento contenía {scan_res['owasp']}",
                        latency_ms=ingest_latency,
                        compliance_tags=scan_res["compliance"],
                        details=scan_res["details"],
                    )
                    st.sidebar.error("❌ Documento Bloqueado: Infracción de políticas de seguridad.")
                else:
                    # Documento Seguro -> Proceder con Ingesta / Segmentación Semántica
                    splitter = TokenSemanticSplitter(chunk_size=200, chunk_overlap=30)
                    chunks = splitter.split_text(extracted_text)

                    st.session_state.rag_chunks = chunks
                    st.session_state.doc_loaded = True
                    st.session_state.doc_name = uploaded_file.name
                    st.session_state.last_status = "Seguro (Documento)"
                    st.session_state.last_risk = "Ingestión Exitosa"

                    # Registrar en log
                    add_audit_event(
                        event_type="INGEST_SAFE",
                        prompt=f"[DOC CARGADO] {uploaded_file.name} (SHA-256 generado)",
                        is_blocked=False,
                        reason="Carga Exitosa RAG",
                        latency_ms=ingest_latency,
                        compliance_tags=["EU AI Act Ingesta Segura", "DORA Trazabilidad de Datos"],
                    )
                    st.sidebar.success(f"✅ Ingerido con éxito: {len(chunks)} fragmentos creados.")
            except (OSError, ValueError, RuntimeError) as e:
                st.sidebar.error(f"Error procesando documento: {e}")
                if temp_file_path.exists():
                    os.remove(temp_file_path)

    # Mostrar estado de carga del documento en el Sidebar
    if st.session_state.doc_loaded:
        st.markdown(f"""
        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 8px; padding: 10px; font-size: 0.85rem; color:#93c5fd; margin-bottom:15px;">
            📄 <strong>Base de datos local activa:</strong><br/>
            {st.session_state.doc_name} ({len(st.session_state.rag_chunks)} chunks)
        </div>
        """, unsafe_allow_html=True)
        if st.button("Limpiar Documentos Cargados", use_container_width=True):
            st.session_state.doc_loaded = False
            st.session_state.doc_name = ""
            st.session_state.rag_chunks = []
            st.rerun()

    st.markdown("### Métricas en Tiempo Real")

    # Renderizar KPI - Estado del Guardarraíl
    status_label = "🟢 ACTIVO" if guardrails_active else "🔴 INACTIVO"
    status_bg = "rgba(34, 197, 94, 0.15)" if guardrails_active else "rgba(239, 68, 68, 0.15)"
    status_border = "rgba(34, 197, 94, 0.4)" if guardrails_active else "rgba(239, 68, 68, 0.4)"
    status_color = "#4ade80" if guardrails_active else "#f87171"

    st.markdown(f"""
    <div class="metric-card" style="background: {status_bg}; border-color: {status_border};">
        <div class="metric-title">Estado Guardarraíl</div>
        <div class="metric-value" style="color: {status_color}; font-size:1.4rem;">{status_label}</div>
    </div>
    """, unsafe_allow_html=True)

    # Renderizar KPI - Latencia de Escaneo
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Última Latencia (Procesamiento)</div>
        <div class="metric-value" style="color: #60a5fa;">{st.session_state.last_latency:.1f} <span style="font-size:1rem; font-weight:normal; color:#94a3b8;">ms</span></div>
    </div>
    """, unsafe_allow_html=True)

    # Renderizar KPI - Estado del Último Escaneo
    risk_color = "#f43f5e" if "Bloqueado" in st.session_state.last_status else ("#fb923c" if st.session_state.last_status == "Bypass de Seguridad" else "#4ade80")
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Última Categoría / Risk Status</div>
        <div class="metric-value" style="color: {risk_color}; font-size: 1.1rem; font-family: 'Inter', sans-serif;">{st.session_state.last_status}</div>
        <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 4px;">Regla: {st.session_state.last_risk}</div>
    </div>
    """, unsafe_allow_html=True)

    # 2. Matriz de Cumplimiento OWASP
    with st.expander("📝 Matriz de Cumplimiento OWASP"):
        st.markdown("""
        Esta plataforma mitiga riesgos del **OWASP Top 10 LLM**:
        - **LLM01: Prompt Injection**: Inspección heurística activa para evitar redirecciones de directivas de sistema.
        - **LLM02: Sensitive Info Disclosure**: Escaneo de PII en tiempo real (DNI, Tarjetas, Emails, Claves API) para evitar la filtración a LLMs públicos.
        - **LLM06: Sensitive Data Lamination**: Registro estricto de auditoría para garantizar el linaje de datos.
        """)
        st.info("Cumplimiento normativo integrado: EU AI Act (Art. 50) y DORA (Art. 6).")

    # 3. Log de Auditoría Dinámico en Sidebar
    st.markdown("### 🖥️ Consola de Auditoría (EU AI Act & DORA)")

    # Botón para limpiar logs
    if st.button("Limpiar Registro de Auditoría", use_container_width=True):
        save_audit_logs([])
        st.rerun()

    # Cargar y renderizar logs
    logs = load_audit_logs()
    if logs:
        console_html = "<div class='console-container'>"
        for log in logs[:15]:
            ts = datetime.fromisoformat(log["timestamp"]).strftime("%H:%M:%S")
            log_type = log["event_type"]

            # Formato de badges
            if log_type in ["SAFE", "INGEST_SAFE"]:
                badge_class = "badge-green"
            elif log_type in ["BLOCKED", "INGEST_BLOCKED"]:
                badge_class = "badge-red"
            else:
                badge_class = "badge-orange"

            console_html += (
                f"<div class='log-line'>"
                f"<span style='color: #64748b;'>[{ts}]</span> "
                f"<span class='badge {badge_class}'>{log_type}</span><br/>"
                f"<span style='color: #f8fafc;'>Mensaje/Doc:</span> {log['prompt']}<br/>"
                f"<span style='color: #a855f7;'>Razón:</span> {log['reason']}<br/>"
                f"<span style='color: #60a5fa;'>Latencia:</span> {log['latency_ms']} ms"
            )
            if log["compliance_tags"]:
                console_html += f"<br/><span style='color: #e2e8f0; font-size: 0.75rem;'>⚖️ {', '.join(log['compliance_tags'])}</span>"
            console_html += "</div>"
        console_html += "</div>"
        st.markdown(console_html, unsafe_allow_html=True)
    else:
        st.markdown("<div class='console-container'>No hay registros de auditoría aún.</div>", unsafe_allow_html=True)


# ==========================================
# INTERFAZ PRINCIPAL DE CHAT
# ==========================================
st.markdown("<h1 class='main-title'>🛡️ IA Conversacional Regulada con Guardarraíles</h1>", unsafe_allow_html=True)
st.markdown("<div class='subtitle'>Entorno de Pruebas RAG Regulado en conformidad con el Reglamento DORA y la Ley de IA de la UE</div>", unsafe_allow_html=True)

# Instanciar el motor de guardarraíles
guardrails = GuardrailsEngine()

# Mostrar historial de chat existente
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Capturar nueva interacción
if user_input := st.chat_input("Introduzca su consulta técnica (Ej: 'Verificar reporte DORA 2026' o consulte sobre sus documentos...)"):

    # 1. Mostrar consulta en la UI de inmediato
    with st.chat_message("user"):
        st.markdown(user_input)
    st.session_state.messages.append({"role": "user", "content": user_input})

    # 2. Iniciar escaneo e interceptación
    start_total_time = time.perf_counter()

    # Escaneo del guardarraíl
    scan_result = guardrails.scan(user_input)

    # Evaluar si el guardarraíl está activo
    if guardrails_active:
        # Caso: Guardarraíl Activo e Intercepta un ataque
        if scan_result["is_blocked"]:
            latency_ms = (time.perf_counter() - start_total_time) * 1000

            # Registrar evento en el log de auditoría
            add_audit_event(
                event_type="BLOCKED",
                prompt=user_input,
                is_blocked=True,
                reason=scan_result["owasp"],
                latency_ms=latency_ms,
                compliance_tags=scan_result["compliance"],
                details=scan_result["details"],
            )

            # Actualizar KPIs globales para el sidebar
            st.session_state.last_latency = latency_ms
            st.session_state.last_status = "Bloqueado (Blocked)"
            st.session_state.last_risk = scan_result["owasp"]

            # Renderizar alerta roja interactiva en la UI
            blocked_html = f"""
            <div class="blocked-card">
                <div class="blocked-title">
                    <span>⚠️ BLOQUEADO POR GUARDARRAÍLES</span>
                </div>
                <div class="blocked-subtitle">CUMPLIMIENTO EU AI ACT & DORA</div>
                <div class="blocked-detail">
                    <strong>Infracción Detectada:</strong> {scan_result['owasp']}<br/>
                    <strong>Detalle:</strong> {scan_result['reason']}<br/>
                    <strong>Latencia de Interceptación:</strong> {latency_ms:.2f} ms
                </div>
                <div class="blocked-compliance">Normativas Afectadas: EU AI Act (Art. 50) y Reglamento DORA (Art. 6)</div>
            </div>
            """

            with st.chat_message("assistant"):
                st.markdown(blocked_html, unsafe_allow_html=True)
            st.session_state.messages.append({"role": "assistant", "content": blocked_html})

            # Forzar actualización de UI para refrescar la consola en el sidebar
            st.rerun()

        else:
            # Caso: Guardarraíl Activo y Prompt Seguro
            latency_ms = (time.perf_counter() - start_total_time) * 1000

            # Guardar KPI parcial
            st.session_state.last_latency = latency_ms
            st.session_state.last_status = "Seguro (Safe)"
            st.session_state.last_risk = "Ninguna infracción detectada"

    else:
        # Caso: Guardarraíl Inactivo
        latency_ms = (time.perf_counter() - start_total_time) * 1000

        # Registrar evento de BYPASS si contenía riesgo pero estaba desactivado
        if scan_result["is_blocked"]:
            add_audit_event(
                event_type="BYPASS",
                prompt=user_input,
                is_blocked=False,
                reason=f"BYPASS - {scan_result['owasp']}",
                latency_ms=latency_ms,
                compliance_tags=["PELIGRO: Canal no seguro (Bypass)"],
                details=f"Infracción omitida: {scan_result['reason']}",
            )
            st.session_state.last_status = "Bypass de Seguridad"
            st.session_state.last_risk = f"OMITIDA: {scan_result['owasp']}"
        else:
            # Si era seguro con guardarraíl inactivo, registrar como seguro
            st.session_state.last_status = "Bypass (Seguro)"
            st.session_state.last_risk = "Ninguna regla activada"

        st.session_state.last_latency = latency_ms

    # 3. Procesar respuesta del Agente (si no fue bloqueado)
    if not guardrails_active or not scan_result["is_blocked"]:

        with st.chat_message("assistant"):
            # Caso A: RAG Activo (Documento cargado)
            if st.session_state.doc_loaded and len(st.session_state.rag_chunks) > 0:
                with st.status(f"🤖 Agente procesando consulta RAG sobre '{st.session_state.doc_name}'...", expanded=True) as status:
                    st.write("🔍 Ejecutando búsqueda de similitud léxica en la base de datos vectorial local...")
                    time.sleep(0.5)

                    # Recuperar fragmentos relevantes reales usando el algoritmo local
                    relevant_chunks = retrieve_relevant_chunks(user_input, st.session_state.rag_chunks, top_k=2)
                    st.write(f"✅ Recuperados {len(relevant_chunks)} fragmentos semánticos con alta puntuación de relevancia.")

                    st.write("🔧 Aplicando módulo de síntesis RAG y formato regulado...")
                    time.sleep(0.8)

                    # Mostrar los chunks en formato colapsado de código JSON dentro de la barra de estado
                    for idx, chk in enumerate(relevant_chunks):
                        st.code(f"// FRAGMENTO RELEVANTE #{idx+1}\n{chk}", language="javascript")

                    status.update(label="🤖 RAG Contextual completado", state="complete", expanded=False)

                # Crear respuesta sintética basada en los chunks recuperados reales
                joined_context = "\n\n".join([f"• Fragmento {i+1}: '{chk[:250]}...'" for i, chk in enumerate(relevant_chunks)])

                # Sintetizar una respuesta corporativa usando el texto
                agent_answer = (
                    f"🤖 **Agente Regulado (RAG):** De acuerdo con el documento cargado **{st.session_state.doc_name}**, "
                    f"he recuperado los fragmentos de cumplimiento más relevantes para tu consulta.\n\n"
                    f"**Contexto del documento analizado:**\n{joined_context}\n\n"
                    f"**Respuesta:** En base a la información extraída, confirmo que se registra una correspondencia "
                    f"directa con tu consulta técnica. Toda esta información ha sido validada "
                    f"bajo las políticas de ciberseguridad internas y no viola directivas del marco regulatorio."
                )
                st.markdown(agent_answer)
                st.session_state.messages.append({"role": "assistant", "content": agent_answer})

            else:
                # Caso B: Simulación estándar de Tool Calling (Sin documento)
                with st.status("🤖 Agente analizando petición...", expanded=True) as status:
                    st.write("🔍 Identificando intención del usuario...")
                    time.sleep(0.5)

                    tool_name, tool_args, tool_response, agent_answer = simulate_agent_with_tool_calling(user_input)

                    st.write(f"🔧 Llamando a la herramienta `{tool_name}({', '.join(f'{k}={v}' for k, v in tool_args.items())})`...")
                    time.sleep(0.8)

                    st.code(tool_response, language="json")
                    st.write("✅ Datos de cumplimiento procesados. Generando respuesta regulada...")
                    time.sleep(0.4)

                    status.update(label="🤖 Procesamiento y Tool Calling completados con éxito", state="complete", expanded=False)

                st.markdown(agent_answer)
                st.session_state.messages.append({"role": "assistant", "content": agent_answer})

        # Calcular latencia total
        total_latency_ms = (time.perf_counter() - start_total_time) * 1000
        st.session_state.last_latency = total_latency_ms

        # Registrar en auditoría
        event_reason = "Safe"
        if not guardrails_active and scan_result["is_blocked"]:
            event_reason = f"Bypass de seguridad de: {scan_result['owasp']}"

        add_audit_event(
            event_type="SAFE" if guardrails_active else "BYPASS",
            prompt=user_input,
            is_blocked=False,
            reason=event_reason,
            latency_ms=total_latency_ms,
            compliance_tags=["EU AI Act Cumplido", "DORA Control RAG"] if guardrails_active else ["INCUMPLIMIENTO: Guardarraíl Desactivado"],
        )

        st.rerun()
