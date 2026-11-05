import datetime
import json
import sys
from pathlib import Path

import streamlit as st

from path_registry import DORA_SCRIPTS, NIS2_DIR, REPORTS_DORA
from shared_utils import run_cli_tool


def render_tab(tab):
    with tab:
        st.header("🚨 Gestión y Notificación de Incidentes")
        st.markdown("Clasificación de Incidentes Mayores y Notificaciones a Autoridades (Art. 17-23).")
        
        st.subheader("1. Calculadora de Clasificación de Incidentes Mayores (DORA Art. 18)")
        with st.form("incident_classifier_form"):
            col_inc1, col_inc2, col_inc3 = st.columns(3)
            with col_inc1:
                clients_affected = st.number_input("Clientes Afectados:", min_value=0, value=150000, step=1000)
                critical_service = st.checkbox("¿Afecta a una Función Esencial o Crítica?", value=True)
            with col_inc2:
                downtime_hours = st.number_input("Tiempo de Indisponibilidad (horas):", min_value=0.0, value=3.5, step=0.5)
                eu_countries = st.number_input("Países de la UE afectados:", min_value=1, value=3, step=1)
            with col_inc3:
                economic_loss = st.number_input("Pérdidas Económicas Estimadas (€):", min_value=0, value=250000, step=10000)
                _impact = st.selectbox("Impacto en Integridad/Confidencialidad:", ["Bajo / Sin Brecha", "Medio", "Alto / Datos Críticos"])
                
            submit_classify = st.form_submit_button("🔍 Clasificar Incidente", use_container_width=True)

        if submit_classify:
            with st.spinner("Evaluando umbrales regulatorios de RTS EBA..."):
                cmd = [
                    sys.executable, str(DORA_SCRIPTS / "21_dora_incident_classifier.py"),
                    "--clients-affected", str(clients_affected),
                    "--downtime-hours", str(downtime_hours),
                    "--economic-loss", str(economic_loss),
                    "--eu-countries", str(eu_countries),
                    "--output-dir", str(REPORTS_DORA)
                ]
                if critical_service:
                    cmd.append("--critical-service")
                
                clf_res = run_cli_tool(cmd)
                st.subheader("Resultado:")
                st.code(clf_res["stdout"] or clf_res["stderr"])

        st.divider()
        st.subheader("2. Generador de Notificación Regulatoria ANC (Art. 19 & 20)")
        current_year = datetime.datetime.now(datetime.timezone.utc).year
        col_not1, col_not2, col_not3 = st.columns(3)
        with col_not1:
            if st.button("📢 Notificación Inicial (2h)", use_container_width=True):
                with st.spinner("Generando alerta inicial..."):
                    res_init = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "23_nca_incident_reporter.py"), "--phase", "initial", "--incident-id", f"INC-{current_year}-001", "--entity-name", "Entidad Regulada", "--output-dir", str(REPORTS_DORA)])
                    st.code(res_init["stdout"] or res_init["stderr"])
        with col_not2:
            if st.button("📢 Informe Intermedio (24h)", use_container_width=True):
                with st.spinner("Generando informe de progreso..."):
                    res_int = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "23_nca_incident_reporter.py"), "--phase", "intermediate", "--incident-id", f"INC-{current_year}-001", "--root-cause", "Fallo de infraestructura / resiliencia", "--output-dir", str(REPORTS_DORA)])
                    st.code(res_int["stdout"] or res_int["stderr"])
        with col_not3:
            if st.button("📢 Informe Final (1 mes)", use_container_width=True):
                with st.spinner("Generando informe final y remediación..."):
                    res_fin = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "23_nca_incident_reporter.py"), "--phase", "final", "--incident-id", f"INC-{current_year}-001", "--title", "Informe Final", "--output-dir", str(REPORTS_DORA)])
                    st.code(res_fin["stdout"] or res_fin["stderr"])

        st.markdown("**Visualización de Reportes JSON ANC**")
        if st.button("👁️ Cargar último reporte generado"):
            report_files = sorted(Path(REPORTS_DORA).glob("nca_report_*.json"), reverse=True)
            if report_files:
                try:
                    with open(report_files[0], "r", encoding="utf-8") as f:
                        data = json.load(f)
                    st.json(data)
                except (OSError, json.JSONDecodeError) as e:
                    st.error(f"Error cargando JSON: {e}")
            else:
                st.warning("No se encontraron reportes NCA en REPORTS/DORA.")

        st.divider()
        st.subheader("3. RCA y Notificación CSIRT NIS2")
        col_rca1, col_rca2 = st.columns(2)
        with col_rca1:
            if st.button("📄 RCA Post-Mortem (ISO 27035)", use_container_width=True):
                with st.spinner("Construyendo reporte de post-mortem..."):
                    rca_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "rca_postmortem_generator.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(rca_res["stdout"] or rca_res["stderr"])
        with col_rca2:
            if st.button("📢 Notificar CSIRT (NIS2 Art. 23)", use_container_width=True):
                with st.spinner("Generando notificación NIS2 CSIRT..."):
                    csirt_res = run_cli_tool([sys.executable, str(NIS2_DIR / "nis2_csirt_notifier.py")])
                    st.code(csirt_res["stdout"] or csirt_res["stderr"])