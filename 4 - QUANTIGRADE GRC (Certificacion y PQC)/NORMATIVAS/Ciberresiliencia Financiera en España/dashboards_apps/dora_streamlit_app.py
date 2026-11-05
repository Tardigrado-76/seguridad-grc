#!/usr/bin/env python3
"""Quantigrade Multi-Normativa Compliance & Audit Platform.

Plataforma empresarial de auditoría continua, gestión de riesgos TIC,
privacidad, gobernanza IA y resiliencia operativa según DORA, NIS2, ENS, RGPD, CRA y EU AI Act.
"""

from __future__ import annotations

import datetime
import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st
import streamlit.web.cli as stcli

from path_registry import REPORTS_DIR

if __name__ == "__main__":
    if not st.runtime.exists():
        sys.argv = ["streamlit", "run", sys.argv[0]]
        sys.exit(stcli.main())

# -----------------------------------------------------------------------------
# Configuración de Página & Marca Quantigrade
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Quantigrade - Multi-Normativa Compliance Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inyección CSS Quantigrade vía st.html nativo (sin markdown escaping)
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
        letter-spacing: 0.5px;
    }

    .block-container {
        padding-top: 1.2rem !important;
        padding-bottom: 1.5rem !important;
    }

    .stButton > button {
        background-color: rgba(0, 229, 255, 0.06) !important;
        border: 1px solid var(--color-accent) !important;
        color: var(--color-accent) !important;
        font-family: 'Montserrat', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: 0.5px;
        transition: all 0.2s ease-in-out;
        border-radius: 4px;
    }

    .stButton > button:hover {
        background-color: rgba(0, 229, 255, 0.18) !important;
        box-shadow: 0 0 15px rgba(0, 229, 255, 0.4) !important;
        color: #FFFFFF !important;
    }

    div[data-baseweb="input"] > div, div[data-baseweb="select"] > div {
        background-color: var(--color-card) !important;
        border: 1px solid var(--color-border) !important;
        color: var(--color-text) !important;
    }
</style>
"""
st.html(QUANTIGRADE_CSS)

# -----------------------------------------------------------------------------
# Localización de Recursos de Marca
# -----------------------------------------------------------------------------
APP_DIR = Path(__file__).resolve().parent
USER_LOGO = APP_DIR / "assets" / "user_logo.png"
QUANTIGRADE_LOGO = APP_DIR / "assets" / "quantigrade_logo.jpg"

if not USER_LOGO.exists():
    fallback_user = Path(r"C:\Users\josel\.gemini\antigravity-ide\brain\2d517000-9dd4-4f1e-a028-75157cfb21c5\.user_uploaded\media_1788297405267.png")
    if fallback_user.exists():
        USER_LOGO = fallback_user

if not QUANTIGRADE_LOGO.exists():
    fallback_quanti = Path(r"E:\PROYECTOS IA\Quantigrade.jpg")
    if fallback_quanti.exists():
        QUANTIGRADE_LOGO = fallback_quanti

# -----------------------------------------------------------------------------
# Gestión de Estado de Sesión & KYC
# -----------------------------------------------------------------------------
DEFAULT_PROJECT_DIR = str(Path(r"E:\PROYECTOS IA\AUDITORIAS\PRODUCTION-READY").resolve())
DEFAULT_REPORTS_DIR = str(REPORTS_DIR.resolve())

if "company_name" not in st.session_state:
    st.session_state.company_name = "QUANTIGRADE SEC"
if "username" not in st.session_state:
    st.session_state.username = "CISO_ADMIN"
if "project_target" not in st.session_state:
    st.session_state.project_target = DEFAULT_PROJECT_DIR
if "reports_target" not in st.session_state:
    st.session_state.reports_target = DEFAULT_REPORTS_DIR


def select_folder(initial_dir: str | None = None) -> str | None:
    """Selector de carpetas en subproceso aislado para evitar bloqueos de hilo."""
    picker_script = APP_DIR / "folder_picker.py"
    if not picker_script.exists():
        return None
    args = [sys.executable, str(picker_script)]
    if initial_dir and os.path.isdir(initial_dir):
        args.append(initial_dir)
    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)  # nosec B603
        out = res.stdout.strip()
        return out if out and os.path.isdir(out) else None
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return None


def cb_browse_project() -> None:
    folder = select_folder(st.session_state.get("project_target"))
    if folder:
        st.session_state.project_target = folder


def cb_browse_reports() -> None:
    folder = select_folder(st.session_state.get("reports_target"))
    if folder:
        st.session_state.reports_target = folder


def cb_reset_paths() -> None:
    st.session_state.project_target = DEFAULT_PROJECT_DIR
    st.session_state.reports_target = DEFAULT_REPORTS_DIR


# -----------------------------------------------------------------------------
# Sidebar: Mini-Dashboard de Postureo & Métricas Regulatorias
# -----------------------------------------------------------------------------
def create_donut_chart(title: str, val_before: int, val_after: int, color: str) -> go.Figure:
    fig = go.Figure()
    fig.add_trace(go.Pie(
        values=[val_before, 100 - val_before],
        hole=0.82,
        marker_colors=[color, "#152A4A"],
        textinfo="none",
        sort=False,
        name="Riesgo Inicial",
        domain={"x": [0, 1], "y": [0, 1]},
    ))
    fig.add_trace(go.Pie(
        values=[val_after, 100 - val_after],
        hole=0.68,
        marker_colors=["#00E5FF", "#152A4A"],
        textinfo="none",
        sort=False,
        name="Post-Mitigación",
        domain={"x": [0.15, 0.85], "y": [0.15, 0.85]},
    ))
    fig.update_layout(
        title={"text": title, "font": {"color": "#E0F2F1", "size": 11, "family": "Montserrat"}},
        showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin={"t": 24, "b": 4, "l": 4, "r": 4},
        height=110,
    )
    return fig


with st.sidebar:
    st.markdown("### 📊 PERFIL DE EXIGENCIA")
    st.caption(f"**ENTIDAD:** `{st.session_state.company_name}`")
    st.caption(f"**OPERADOR:** `{st.session_state.username}`")

    with st.expander("👤 Modificar Datos KYC"):
        new_company = st.text_input("Empresa / Entidad:", value=st.session_state.company_name)
        new_user = st.text_input("Operador CISO:", value=st.session_state.username)
        if st.button("Guardar KYC", use_container_width=True):
            st.session_state.company_name = new_company.strip() or "QUANTIGRADE SEC"
            st.session_state.username = new_user.strip() or "CISO_ADMIN"
            st.rerun()

    st.divider()
    st.markdown("**Postura de Riesgo (Antes vs. Después):**")

    # Donut charts de postureo
    st.plotly_chart(create_donut_chart("RESILIENCIA (DORA)", 85, 18, "#FF2A2A"), use_container_width=True, config={"displayModeBar": False})
    st.plotly_chart(create_donut_chart("CADENA SUMINISTRO (NIS2)", 78, 22, "#FF8C00"), use_container_width=True, config={"displayModeBar": False})
    st.plotly_chart(create_donut_chart("SEGURIDAD SISTEMA (ENS)", 92, 12, "#00E5FF"), use_container_width=True, config={"displayModeBar": False})
    st.plotly_chart(create_donut_chart("PRIVACIDAD (RGPD)", 80, 15, "#76FF03"), use_container_width=True, config={"displayModeBar": False})

    st.divider()
    st.metric(label="Modo de Ejecución", value="HITL Zero Trust", delta="DORA Art. 9")
    st.caption(f"Directorio de Reportes:\n`{st.session_state.reports_target}`")

# -----------------------------------------------------------------------------
# Cabecera Principal (Mi Logo junto a Quantigrade)
# -----------------------------------------------------------------------------
current_date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

col_user_logo, col_quanti_logo, col_title_text, col_status_badge = st.columns(
    [0.08, 0.08, 0.60, 0.24],
    vertical_alignment="center",
)

with col_user_logo:
    if USER_LOGO.exists():
        st.image(str(USER_LOGO), width=58)
    else:
        st.markdown("## 🛡️")

with col_quanti_logo:
    if QUANTIGRADE_LOGO.exists():
        st.image(str(QUANTIGRADE_LOGO), width=58)

with col_title_text:
    st.markdown(f"### PORTAL DE CUMPLIMIENTO {st.session_state.company_name.upper()}")
    st.caption(f"🛡️ **Quantigrade Multi-Normativa Suite** | Operador: `{st.session_state.username}` | Estado: `🟢 AUTENTICADO`")

with col_status_badge:
    st.info(f"📅 **{current_date_str} (UTC)**\n\n🟢 **Estado: Operativo**")

st.divider()

# -----------------------------------------------------------------------------
# Panel Central de Parámetros (Rutas con Explorer & Reset)
# -----------------------------------------------------------------------------
st.markdown("#### 📁 Panel Central de Rutas de Auditoría")
pcol1, pcol2, pcol3 = st.columns([4.2, 4.2, 1.6], vertical_alignment="bottom")

with pcol1:
    st.caption("RUTA DE EVIDENCIAS / PROYECTO:")
    c_in1, c_in2 = st.columns([7.5, 2.5])
    with c_in1:
        st.text_input("Ruta Proyecto", key="project_target", label_visibility="collapsed")
    with c_in2:
        st.button("📁 Explorar", key="btn_in", on_click=cb_browse_project, use_container_width=True)

with pcol2:
    st.caption("DIRECTORIO DE REPORTES / EXPORTACIÓN:")
    c_out1, c_out2 = st.columns([7.5, 2.5])
    with c_out1:
        st.text_input("Ruta Reportes", key="reports_target", label_visibility="collapsed")
    with c_out2:
        st.button("📁 Explorar", key="btn_out", on_click=cb_browse_reports, use_container_width=True)

with pcol3:
    st.button("🔄 Resetear", key="btn_reset", on_click=cb_reset_paths, use_container_width=True, help="Restablecer rutas por defecto")

st.divider()

# -----------------------------------------------------------------------------
# Navegación Operativa (8 Módulos Especializados)
# -----------------------------------------------------------------------------
tabs = st.tabs([
    "🛠️ 1. Código & Supply Chain",
    "🏢 2. Proveedores TIC & RoI",
    "🚨 3. Incidentes & ANC",
    "💥 4. Resiliencia & Caos",
    "🔐 5. Criptografía & Hardening",
    "🌍 6. Auditoría Multi-Normativa",
    "🇪🇺 7. Privacidad & RGPD",
    "🤖 8. EU AI Act & LLM Guardrails",
])

from tabs import (
    tab_1_codigo,
    tab_2_proveedores,
    tab_3_incidentes,
    tab_4_resiliencia,
    tab_5_criptografia,
    tab_6_multi,
    tab_7_rgpd,
    tab_8_ai,
)

tab_1_codigo.render_tab(tabs[0])
tab_2_proveedores.render_tab(tabs[1])
tab_3_incidentes.render_tab(tabs[2])
tab_4_resiliencia.render_tab(tabs[3])
tab_5_criptografia.render_tab(tabs[4])
tab_6_multi.render_tab(tabs[5])
tab_7_rgpd.render_tab(tabs[6])
tab_8_ai.render_tab(tabs[7])
