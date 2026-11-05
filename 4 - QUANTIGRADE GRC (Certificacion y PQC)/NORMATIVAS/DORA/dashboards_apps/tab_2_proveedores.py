import sys

import streamlit as st

from path_registry import DORA_SCRIPTS, NIS2_DIR, REPORTS_DORA
from shared_utils import run_cli_tool


def render_tab(tab):
    with tab:
        st.header("🏢 Proveedores TIC, RoI & TRM")
        st.markdown("Gestión de Riesgo de Terceros (Art. 28-44) y NIS2 TRM.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📋 Registro de Información (RoI)")
            if st.button("📊 Generar Registro de Proveedores", use_container_width=True):
                with st.spinner("Compilando plantillas RoI..."):
                    roi_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "02_generate_dora_roi.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(roi_res["stdout"] or roi_res["stderr"])
                    
            st.subheader("🕵️ Escáner de Proveedores TRM (NIS2)")
            if st.button("🔍 Escanear Riesgos de Proveedor TRM", use_container_width=True):
                with st.spinner("Ejecutando Threat Risk Management Scanner..."):
                    trm_res = run_cli_tool([sys.executable, str(NIS2_DIR / "trm_vendor_scanner.py")])
                    st.code(trm_res["stdout"] or trm_res["stderr"])
                    
        with col2:
            st.subheader("⚖️ Riesgo de Concentración TIC")
            if st.button("📈 Auditar Concentración de Proveedores", use_container_width=True):
                with st.spinner("Analizando concentración y subcontratación..."):
                    conc_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "dora_ict_third_party_risk_auditor.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(conc_res["stdout"] or conc_res["stderr"])