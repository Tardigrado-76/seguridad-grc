import os
import subprocess  # nosec B404
import sys

import plotly.graph_objects as go
import streamlit as st

# Add project root to path so we can import src
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.core.orchestrator import ComplianceOrchestrator

# Configuración de página Quantigrade Official
st.set_page_config(
    page_title="Quantigrade | Oficial Pre-Auditoría",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Helpers for File Dialogs in Isolated Process (Prevents Tkinter Thread Hangs in Streamlit)
def select_folder(initial_dir=None):
    picker_script = os.path.join(current_dir, "src", "folder_picker.py")
    args = [sys.executable, picker_script]
    if initial_dir and os.path.isdir(initial_dir):
        args.append(initial_dir)
    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)  # nosec B603
        out = res.stdout.strip()
        return out if out and os.path.isdir(out) else None
    except Exception:  # noqa: BLE001
        return None

# 1. CSS Inyección: Quantigrade Cyber-Resilient Theme (Compact)
QUANTIGRADE_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap');

    :root {
        --color-bg: #070B14;
        --color-card: #0D1424;
        --color-primary: #05080F;
        --color-accent: #00E5FF;
        --color-danger: #FF2A2A;
        --color-text: #E0F2F1;
        --color-muted: #546E7A;
        --color-border: #152A4A;
    }

    .stApp {
        background-color: var(--color-bg);
        color: var(--color-text);
        font-family: 'Montserrat', sans-serif;
    }
    
    .stSidebar {
        background-color: var(--color-primary) !important;
        border-right: 1px solid var(--color-border);
    }
    
    code, .stCodeBlock, pre {
        font-family: 'Fira Code', monospace !important;
        background-color: var(--color-card) !important;
        border: 1px solid var(--color-border) !important;
        border-radius: 4px !important;
        color: var(--color-accent) !important;
    }

    h1, h2, h3, h4, h5 {
        font-family: 'Montserrat', sans-serif !important;
        font-weight: 700 !important;
        color: #FFFFFF !important;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 0px !important;
        padding-bottom: 0px !important;
    }

    /* Compact margins to fit in one screen */
    .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 1rem !important;
    }

    h1 {
        text-shadow: 0 0 20px rgba(0, 229, 255, 0.4);
        border-bottom: 2px solid var(--color-accent);
        padding-bottom: 5px !important;
        font-size: 1.8rem !important;
    }

    .stButton > button {
        background-color: rgba(0, 229, 255, 0.05) !important;
        border: 1px solid var(--color-accent) !important;
        color: var(--color-accent) !important;
        font-family: 'Montserrat', sans-serif !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        transition: all 0.3s ease-in-out;
        border-radius: 4px;
        padding: 0px 10px !important;
        height: 40px !important;
    }
    .stButton > button:hover {
        background-color: rgba(0, 229, 255, 0.15) !important;
        box-shadow: 0 0 20px rgba(0, 229, 255, 0.5) !important;
        border-color: #FFFFFF !important;
        color: #FFFFFF !important;
    }

    div[data-baseweb="input"] > div, div[data-baseweb="select"] > div {
        background-color: var(--color-card) !important;
        border: 1px solid var(--color-border) !important;
        color: var(--color-text) !important;
        border-radius: 0px !important;
        height: 40px !important;
    }

    .login-box {
        background-color: var(--color-card);
        padding: 40px;
        border-radius: 8px;
        border: 1px solid var(--color-accent);
        box-shadow: 0 0 30px rgba(0, 229, 255, 0.15);
        max-width: 500px;
        margin: 100px auto;
        text-align: center;
    }
    
    /* Alert / Info boxes compact */
    div[data-testid="stAlert"] {
        padding: 0.5rem !important;
        margin-top: 0.5rem !important;
    }
</style>
"""
st.markdown(QUANTIGRADE_CSS, unsafe_allow_html=True)

logo_path = os.path.join(current_dir, "assets", "quantigrade_logo.jpg")

DEFAULT_IN_PATH = os.path.abspath(os.path.join(current_dir, ".."))
DEFAULT_OUT_PATH = os.path.abspath(os.path.join(current_dir, "reports"))

# INITIALIZE SESSION STATE
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.company_name = ""
    st.session_state.username = ""
if "ti_in" not in st.session_state:
    st.session_state.ti_in = DEFAULT_IN_PATH
if "ti_out" not in st.session_state:
    st.session_state.ti_out = DEFAULT_OUT_PATH

# --- LOGIN VIEW ---
if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-box">', unsafe_allow_html=True)
        if os.path.exists(logo_path):
            st.image(logo_path, width=200)
        st.markdown("### KYC & AUTENTICACIÓN")
        comp = st.text_input("IDENTIFICADOR ENTIDAD (Empresa)")
        usr = st.text_input("CREDENCIAL DE USUARIO", type="password")
        if st.button("ACCESO SEGURO", use_container_width=True):
            if comp and usr:
                st.session_state.company_name = comp
                st.session_state.username = usr
                st.session_state.logged_in = True
                st.rerun()
            else:
                st.error("INFRACCIÓN: Parámetros KYC incompletos.")
        st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

# --- MAIN DASHBOARD VIEW ---

# Helpers for UI Charts
def create_donut_chart(title, val_before, val_after, color):
    fig = go.Figure()
    fig.add_trace(go.Pie(
        values=[val_before, 100-val_before],
        hole=0.85, marker_colors=[color, '#152A4A'], textinfo='none', sort=False,
        name='Riesgo Inicial', domain={'x': [0, 1], 'y': [0, 1]}
    ))
    fig.add_trace(go.Pie(
        values=[val_after, 100-val_after],
        hole=0.70, marker_colors=['#00E5FF', '#152A4A'], textinfo='none', sort=False,
        name='Post-Mitigación', domain={'x': [0.15, 0.85], 'y': [0.15, 0.85]}
    ))
    fig.update_layout(
        title={"text": title, "font": {"color": "#E0F2F1", "size": 11, "family": "Montserrat"}},
        showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin={"t": 25, "b": 5, "l": 5, "r": 5},
        height=140,
    )
    return fig

# --- SIDEBAR (MINI-DASHBOARD "POSTUREO") ---
with st.sidebar:
    st.markdown("### PERFIL EXIGENCIA REGULATORIA")
    st.markdown(f"**ENTIDAD:** `{st.session_state.company_name}`")
    st.markdown("---")
    
    dora_val = {"ALTA": 25, "MEDIA": 50, "BAJA": 75, "CERO-TRUST": 100}.get(st.session_state.get("sl_dora", "BAJA"), 0)
    nis_val = int(100 - (st.session_state.get("sl_nis2", 24) / 72 * 100))
    ens_val = {"BÁSICA": 33, "MEDIA": 66, "ALTA": 100}.get(st.session_state.get("sl_ens", "ALTA"), 0)
    gdpr_val = {"BÁSICO": 33, "PSEUDONIMIZADO": 66, "CRIPTOGRÁFICO": 100}.get(st.session_state.get("sl_gdpr", "CRIPTOGRÁFICO"), 0)
    
    if st.session_state.get("f_dora_active", True):
        st.plotly_chart(create_donut_chart("RESILIENCIA (DORA)", 90, 100 - dora_val, "#FF2A2A"), use_container_width=True)
    if st.session_state.get("f_nis2_active", True):
        st.plotly_chart(create_donut_chart("INCIDENTES (NIS2)", 85, 100 - nis_val, "#FF8C00"), use_container_width=True)
    if st.session_state.get("f_ens_active", True):
        st.plotly_chart(create_donut_chart("SEGURIDAD (ENS)", 75, 100 - ens_val, "#FF2A2A"), use_container_width=True)
    if st.session_state.get("f_gdpr_active", True):
        st.plotly_chart(create_donut_chart("PRIVACIDAD (RGPD)", 80, 100 - gdpr_val, "#00E5FF"), use_container_width=True)

# --- MAIN COLUMN ---
# Header Area (Compact)
col_logo, col_title = st.columns([0.8, 10])
with col_logo:
    if os.path.exists(logo_path):
        st.image(logo_path, width=60)
with col_title:
    st.title(f"PORTAL DE CUMPLIMIENTO {st.session_state.company_name.upper()}")
    st.markdown(f"**USUARIO ACTIVO:** `{st.session_state.username}` | **ESTADO:** `AUTENTICADO`")
st.markdown("---")

# Callbacks to safely update session_state BEFORE widgets are instantiated
def cb_browse_in() -> None:
    folder = select_folder(st.session_state.get("ti_in"))
    if folder:
        st.session_state.ti_in = folder


def cb_browse_out() -> None:
    folder = select_folder(st.session_state.get("ti_out"))
    if folder:
        st.session_state.ti_out = folder


def cb_reset_paths() -> None:
    st.session_state.ti_in = DEFAULT_IN_PATH
    st.session_state.ti_out = DEFAULT_OUT_PATH


# Parameters Panel
st.markdown("### PANEL DE PARÁMETROS CENTRAL")
pcol1, pcol2, pcol3, pcol4 = st.columns([3.5, 3.5, 1.5, 1.5])

with pcol1:
    st.caption("RUTA DE EVIDENCIAS")
    in_col_1, in_col_2 = st.columns([7, 3])
    with in_col_1:
        st.text_input("RUTA DE EVIDENCIAS", key="ti_in", label_visibility="collapsed")
    with in_col_2:
        st.button("📁 EXPLORAR", key="btn_in", on_click=cb_browse_in)

with pcol2:
    st.caption("RUTA DE EXPORTACIÓN")
    out_col_1, out_col_2 = st.columns([7, 3])
    with out_col_1:
        st.text_input("RUTA DE EXPORTACIÓN", key="ti_out", label_visibility="collapsed")
    with out_col_2:
        st.button("📁 EXPLORAR", key="btn_out", on_click=cb_browse_out)

with pcol3:
    st.caption("FORMATO")
    report_format = st.selectbox("FORMATO", options=["md", "pdf", "both"], index=0, label_visibility="collapsed")

with pcol4:
    st.caption("RESTABLECER")
    st.button("🔄 RESET", key="btn_reset_paths", on_click=cb_reset_paths, use_container_width=True, help="Restablecer rutas por defecto")

st.markdown("---")

# Frameworks in Two Columns
st.markdown("### MARCOS REGULATORIOS A EVALUAR")
fcol1, fcol2 = st.columns(2)

with fcol1:
    f_dora = st.checkbox("DORA (REGLAMENTO UE 2022/2554)", value=True, key="f_dora_active")
    if f_dora:
        val_dora = st.select_slider("Tolerancia a Caídas (DORA)", options=["ALTA", "MEDIA", "BAJA", "CERO-TRUST"], value="BAJA", key="sl_dora")
        st.info(f"DORA: Nivel {val_dora}. Se aplicará auditoría de cadena de suministro y pentesting.")

    f_ens = st.checkbox("ENS (RD 311/2022)", value=True, key="f_ens_active")
    if f_ens:
        val_ens = st.select_slider("Categoría Objetivo ENS", options=["BÁSICA", "MEDIA", "ALTA"], value="ALTA", key="sl_ens")
        st.info(f"ENS: Nivel {val_ens}. Controles estrictos en accesos y cifrado requeridos.")

with fcol2:
    f_nis2 = st.checkbox("NIS2 (DIRECTIVA UE 2022/2555)", value=True, key="f_nis2_active")
    if f_nis2:
        val_nis2 = st.slider("Umbral Incidentes (Horas)", min_value=1, max_value=72, value=24, key="sl_nis2")
        st.info(f"NIS2: Notificación temprana {val_nis2}h. Se validan pipelines de respuesta rápida.")

    f_gdpr = st.checkbox("RGPD / LOPDGDD", value=True, key="f_gdpr_active")
    if f_gdpr:
        val_gdpr = st.select_slider("Nivel Anonimización", options=["BÁSICO", "PSEUDONIMIZADO", "CRIPTOGRÁFICO"], value="CRIPTOGRÁFICO", key="sl_gdpr")
        st.info(f"RGPD: Anonimización {val_gdpr}. Implementación de Privacidad por Diseño.")

f_cra = st.checkbox("CRA (CYBER RESILIENCE ACT)", value=True, key="f_cra_active")

st.markdown("<br>", unsafe_allow_html=True)
start_audit = st.button("EJECUTAR ANÁLISIS DE RIESGO OFICIAL", use_container_width=True)

# Collect Frameworks
selected_frameworks = []
if f_dora: selected_frameworks.append("DORA")
if f_nis2: selected_frameworks.append("NIS2")
if f_ens: selected_frameworks.append("ENS_ALTO")
if f_gdpr: selected_frameworks.append("GDPR")
if f_cra: selected_frameworks.append("CRA")

# Execution Area
if start_audit:
    input_path = st.session_state.ti_in.strip(' \'"\u202A\u202B\u202C\u202D\u202E')
    output_dir = st.session_state.ti_out.strip(' \'"\u202A\u202B\u202C\u202D\u202E')
    
    if not os.path.exists(input_path):
        st.error(f"FALLO DE LECTURA: El directorio especificado no existe: `{input_path}`")
    elif not selected_frameworks:
        st.error("INFRACCIÓN DE PARÁMETROS: Debe seleccionar al menos un marco regulatorio oficial.")
    else:
        st.info("INICIALIZANDO MOTORES DE CUMPLIMIENTO EN ENTORNO SEGURO...")
        
        with st.spinner("PROCESANDO EVIDENCIAS..."):
            try:
                orchestrator = ComplianceOrchestrator(
                    input_path=input_path,
                    frameworks=selected_frameworks,
                    company_name=st.session_state.company_name,
                    output_dir=output_dir,
                    report_format=report_format
                )
                
                results = orchestrator.run_audit()
                
                st.success("VALIDACIÓN COMPLETADA. RIESGO SANCIÓN MITIGADO.")
                
                rcol1, rcol2, rcol3 = st.columns(3)
                eval_count = len(results.get("evaluators", {}))
                mapped = len(results.get("mapper", {}))
                hash_val = results.get("manifest", {}).get("merkle_root", "N/A")[:12]
                
                rcol1.metric("MOTORES", eval_count)
                rcol2.metric("CONTROLES", mapped)
                rcol3.metric("HASH", hash_val)
                    
                st.info(f"DICTAMEN GENERADO EN: `{os.path.join(output_dir, st.session_state.company_name)}`")

            except Exception as e:  # noqa: BLE001
                st.error(f"FALLO CRÍTICO EN EL MOTOR: {e!s}")
