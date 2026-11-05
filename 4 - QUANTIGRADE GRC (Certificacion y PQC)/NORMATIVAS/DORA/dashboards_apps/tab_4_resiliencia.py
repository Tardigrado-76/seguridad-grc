import sys

import streamlit as st

from path_registry import DORA_SCRIPTS, REPORTS_DORA, RESILIENCE_DIR, SOAR_DIR
from shared_utils import run_cli_tool


def render_tab(tab):
    with tab:
        st.header("⚡ Pruebas de Resiliencia Digital, TLPT y Salida Cloud")
        st.markdown("Validación de DORA Artículos 25 y 26, y Chaos Engineering.")
        
        col_res1, col_res2 = st.columns(2)
        with col_res1:
            st.subheader("☁️ Estrategia de Salida Cloud (Art. 28.8)")
            if st.button("🔄 Simular Estrategia de Salida (Dry-Run)", use_container_width=True):
                with st.spinner("Simulando migración de contingencia y validación de RTO/RPO..."):
                    exit_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "16_cloud_exit_strategy_test.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(exit_res["stdout"] or exit_res["stderr"])
                    
            st.subheader("💥 Simulación de Estrés y DDoS (Art. 26)")
            if st.button("🧨 Ejecutar Test de Estrés (Dry-Run)", use_container_width=True):
                with st.spinner("Evaluando respuesta de WAF y Rate-Limiting..."):
                    ddos_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "17_ddos_simulator.py"), "--target-url", "http://127.0.0.1:8000/health", "--dry-run", "--output-dir", str(REPORTS_DORA)])
                    st.code(ddos_res["stdout"] or ddos_res["stderr"])
                    
            st.subheader("🌪️ Chaos Engineering DORA (Panic Switch)")
            if st.button("⚠️ Ejecutar Chaos Resilience Tester", use_container_width=True):
                with st.spinner("Evaluando resiliencia extrema Art. 25..."):
                    chaos_res = run_cli_tool([sys.executable, str(RESILIENCE_DIR / "dora_chaos_resilience_tester.py")])
                    st.code(chaos_res["stdout"] or chaos_res["stderr"])

        with col_res2:
            st.subheader("🎯 Métricas TLPT (TIBER-EU)")
            if st.button("📊 Recopilar Evidencias TLPT", use_container_width=True):
                with st.spinner("Calculando tiempos medios de detección y respuesta..."):
                    tlpt_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "18_tlpt_evidence_collector.py"), "--simulate-exercise", "--output-dir", str(REPORTS_DORA)])
                    st.code(tlpt_res["stdout"] or tlpt_res["stderr"])
                    
            st.subheader("🔄 Conmutación por Error (Failover)")
            if st.button("🔁 Simular Failover Automatizado", use_container_width=True):
                with st.spinner("Verificando conmutación a nodo secundario..."):
                    failover_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "dora_automated_failover_drill.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(failover_res["stdout"] or failover_res["stderr"])
                    
            st.subheader("🤖 SOAR & Event Driven Auditor")
            if st.button("📡 Iniciar SOAR Orchestrator (Demo)", use_container_width=True):
                with st.spinner("Monitorizando eventos en bus..."):
                    soar_res = run_cli_tool([sys.executable, str(SOAR_DIR / "soar_orchestrator.py")], timeout=10)
                    st.code(soar_res["stdout"] or soar_res["stderr"])