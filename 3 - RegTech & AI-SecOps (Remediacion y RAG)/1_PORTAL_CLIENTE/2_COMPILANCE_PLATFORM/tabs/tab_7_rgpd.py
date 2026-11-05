import sys

import streamlit as st

from path_registry import PRODUCTION_READY, RGPD_DIR
from shared_utils import run_cli_tool, run_ps1_tool


def render_tab(tab):
    with tab:
        st.header("🇪🇺 Privacidad & RGPD")
        st.markdown("Herramientas operativas para el cumplimiento del RGPD y LOPDGDD.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🚨 Gestión de Brechas de Datos y AEPD")
            st.markdown("Notificación a la AEPD en 72h (Art. 33-34).")
            with st.form("breach_form"):
                _nature = st.text_input("Naturaleza de la brecha:")
                _records = st.number_input("Registros afectados:", min_value=0, value=100)
                _category = st.selectbox("Categorías de datos:", ["Básicos", "Sensibles/Especiales (Art. 9)", "Financieros"])
                if st.form_submit_button("📢 Generar Notificación AEPD", type="primary"):
                    with st.spinner("Generando evaluación de riesgo y notificación AEPD..."):
                        res = run_cli_tool([sys.executable, str(RGPD_DIR / "rgpd_data_breach_auditor.py")])
                        st.code(res["stdout"] or res["stderr"])
                        
            st.subheader("🗑️ Retención y Purgado")
            if st.button("🧹 Purgar Datos Vencidos (Art. 5)"):
                with st.spinner("Identificando y eliminando datos fuera de política..."):
                    res = run_cli_tool([sys.executable, str(RGPD_DIR / "rgpd_data_retention_purger.py")])
                    st.code(res["stdout"] or res["stderr"])
                    
        with col2:
            st.subheader("📋 Derechos ARCO (SAR)")
            st.markdown("Derecho de acceso y portabilidad (Art. 15-20).")
            with st.form("sar_form"):
                st.text_input("ID del Interesado (Email/UUID):")
                if st.form_submit_button("📥 Extraer Datos del Interesado"):
                    with st.spinner("Recopilando datos estructurados..."):
                        res = run_cli_tool([sys.executable, str(RGPD_DIR / "sar_data_extractor.py")])
                        st.code(res["stdout"] or res["stderr"])
                        
            st.subheader("🔒 Pseudonimización Real (PS1)")
            st.markdown("Medidas de seguridad (Art. 32). Requiere ejecución en entorno seguro.")
            if st.button("🛡️ Ejecutar Pseudonimizador PowerShell", type="primary"):
                with st.spinner("Aplicando algoritmos de pseudonimización y tokenización..."):
                    script_path = PRODUCTION_READY / "compliance-frameworks" / "RGPD - LOPDGDD" / "rgpd_data_pseudonymizer.ps1"
                    if script_path.exists():
                        res = run_ps1_tool(str(script_path))
                        st.success("Proceso de pseudonimización completado.")
                        st.code(res["stdout"] or res["stderr"])
                    else:
                        st.error(f"No se encuentra el script en: {script_path}")