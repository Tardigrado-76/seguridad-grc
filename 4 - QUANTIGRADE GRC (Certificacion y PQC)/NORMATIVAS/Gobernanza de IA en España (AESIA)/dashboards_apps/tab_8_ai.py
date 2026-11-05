import json
import subprocess  # nosec B404
import sys

import streamlit as st

from path_registry import (
    AI_GOVERNANCE_DIR,
    AI_GUARDRAILS_DIR,
    AI_RESILIENCE_DIR,
    AI_SECURITY_DIR,
    PRODUCTION_READY,
    RAG_GUARDRAILS_DIR,
    RAG_INGESTION_PIPELINE,
    RAG_REGULADO_APP,
    REPORTS_OWASP,
)
from shared_utils import run_cli_tool


def render_tab(tab):
    with tab:
        st.header("🤖 EU AI Act & Seguridad LLM (OWASP Guardrails)")
        st.markdown(
            "Plataforma operativa de gobernanza de IA (**Reglamento UE 2024/1689**), "
            "mitigación activa del **OWASP LLM Top 10** y RAG Regulado con linaje criptográfico."
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🇪🇺 Gobernanza EU AI Act (Reg. 2024/1689)")
            
            ai_engine_path = PRODUCTION_READY / "compliance-frameworks" / "EU AI Act" / "ai_compliance_engine.py"
            if st.button("⚖️ Ejecutar Auditoría EU AI Act (3 Fases: OSINT + CISO + Remediación)", use_container_width=True, type="primary"):
                with st.spinner("Auditando nivel de riesgo, obligaciones de transparencia y controles técnicos..."):
                    engine_script = str(ai_engine_path) if ai_engine_path.exists() else str(AI_GOVERNANCE_DIR / "ai_compliance_auditor.py")
                    res = run_cli_tool([sys.executable, engine_script])
                    st.code(res["stdout"] or res["stderr"])
                    
            if st.button("👁️ Verificar Supervisión Humana HITL (Art. 14)", use_container_width=True):
                with st.spinner("Analizando registros de intervención humana y trace context..."):
                    res = run_cli_tool([sys.executable, str(AI_GOVERNANCE_DIR / "eu_ai_act_human_oversight_auditor.py")])
                    st.code(res["stdout"] or res["stderr"])
                    
            if st.button("💧 Aplicar Watermarking Criptográfico a Modelos (Art. 50)", use_container_width=True):
                with st.spinner("Incrustando marcas de agua criptográficas y verificación de integridad..."):
                    res = run_cli_tool([sys.executable, str(AI_GOVERNANCE_DIR / "eu_ai_act_model_watermarker.py")])
                    st.code(res["stdout"] or res["stderr"])
                    
            if st.button("📜 Firmar Procedencia de Modelos y Anti-Poisoning (Art. 10)", use_container_width=True):
                with st.spinner("Asegurando hashes de tensores y firma de linaje de datos..."):
                    res = run_cli_tool([sys.executable, str(AI_GOVERNANCE_DIR / "ai_model_provenance_signer.py")])
                    st.code(res["stdout"] or res["stderr"])

            st.divider()
            st.subheader("📚 Evidencias y Auditoría RAG Regulado")
            audit_log_file = RAG_GUARDRAILS_DIR / "audit_log.json"
            if audit_log_file.exists():
                st.caption(f"Registro de Auditoría en Tiempo Real: `{audit_log_file.name}`")
                with st.expander("🔍 Ver Trazas de Auditoría (DORA Art. 6 / EU AI Act Art. 12)"):
                    try:
                        st.json(audit_log_file.read_text(encoding="utf-8"))
                    except (OSError, ValueError, json.JSONDecodeError) as ex:
                        st.error(f"Error leyendo audit_log: {ex}")

        with col2:
            st.subheader("🛡️ Seguridad LLM (OWASP Top 10) & RAG Regulado")
            
            # RAG Ingestion Pipeline
            if st.button("📦 Pipeline de Ingesta Segura (Sanitización & Linaje SHA-256)", use_container_width=True):
                with st.spinner("Ejecutando pipeline con sanitización Path Traversal y enmascaramiento PII (RGPD)..."):
                    sample_dir = RAG_GUARDRAILS_DIR
                    output_file = REPORTS_OWASP / "rag_ingest_report.json"
                    cmd = [
                        sys.executable, str(RAG_INGESTION_PIPELINE),
                        "-d", str(sample_dir),
                        "-o", str(output_file),
                        "--mask-pii",
                        "--max-file-size-mb", "2.0"
                    ]
                    res = run_cli_tool(cmd, timeout=60)
                    st.code(res["stdout"] or res["stderr"])
                    if output_file.exists():
                        st.success(f"Reporte de ingesta generado en: {output_file}")
            
            # Interactive Regulated RAG launch
            st.markdown("**Plataforma de Conversación Segura RAG**")
            col_rag_a, col_rag_b = st.columns(2)
            with col_rag_a:
                if st.button("🚀 Lanzar RAG Regulado (Port 8503)", use_container_width=True):
                    try:
                        subprocess.Popen(  # nosec B603
                            [sys.executable, "-m", "streamlit", "run", str(RAG_REGULADO_APP), "--server.port", "8503", "--server.headless", "true"],
                            cwd=str(RAG_GUARDRAILS_DIR)
                        )
                        st.success("RAG Regulado lanzado en http://localhost:8503")
                    except (OSError, RuntimeError) as e:
                        st.error(f"Error lanzando RAG: {e}")
            with col_rag_b:
                st.link_button("🌐 Abrir RAG (Puerto 8503)", "http://localhost:8503", use_container_width=True)

            st.divider()
            st.markdown("**Controles Complementarios OWASP LLM**")
            col_sub1, col_sub2 = st.columns(2)
            with col_sub1:
                if st.button("🚧 Gateway LLM Guard", use_container_width=True):
                    with st.spinner("Activando filtros de seguridad..."):
                        res = run_cli_tool([sys.executable, str(AI_GUARDRAILS_DIR / "ai_sec_guard.py")])
                        st.code(res["stdout"] or res["stderr"])
                if st.button("🍯 Honeypot Jailbreak", use_container_width=True):
                    with st.spinner("Activando detección de ataques..."):
                        res = run_cli_tool([sys.executable, str(AI_SECURITY_DIR / "llm_autonomous_agent_jailbreak_honeypot.py")])
                        st.code(res["stdout"] or res["stderr"])
            with col_sub2:
                if st.button("☠️ Data Poisoning Audit", use_container_width=True):
                    with st.spinner("Inspeccionando base de datos vectorial..."):
                        res = run_cli_tool([sys.executable, str(AI_SECURITY_DIR / "llm_rag_data_poisoning_auditor.py")])
                        st.code(res["stdout"] or res["stderr"])
                if st.button("⏱️ Rate Limiter DoS", use_container_width=True):
                    with st.spinner("Protegiendo inferencia DoS..."):
                        res = run_cli_tool([sys.executable, str(AI_RESILIENCE_DIR / "llm_token_ratelimiter.py")])
                        st.code(res["stdout"] or res["stderr"])

            manual_file = RAG_GUARDRAILS_DIR / "Manual_Usuario.md"
            if manual_file.exists():
                with st.expander("📖 Manual de Usuario & Guía de Guardrails OWASP"):
                    try:
                        st.markdown(manual_file.read_text(encoding="utf-8"))
                    except (OSError, RuntimeError) as e:
                        st.error(f"Error leyendo manual: {e}")