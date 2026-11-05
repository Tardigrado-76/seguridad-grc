import sys

import streamlit as st

from path_registry import (
    DORA_SCRIPTS,
    PRODUCTION_READY,
    REPORTS_DORA,
    SAST_DAST_DIR,
    SUPPLY_CHAIN_DIR,
)
from shared_utils import run_cli_tool


def render_tab(tab):
    with tab:
        st.header("🔍 Auditoría de Código & Supply Chain")
        st.markdown("Validación de seguridad en el SDLC (DORA Art. 9) y CRA.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📦 Lista de Materiales de Software (SBOM)")
            if st.button("🚀 Generar SBOM (CycloneDX 1.6)", use_container_width=True):
                with st.spinner("Escaneando dependencias y firmando SBOM..."):
                    sbom_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "01_generate_sbom.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(sbom_res["stdout"] or sbom_res["stderr"])
            
            st.subheader("🛡️ Escaneo de Vulnerabilidades (AST)")
            if st.button("🚀 Ejecutar SAST/DAST Security Scan", use_container_width=True):
                with st.spinner("Analizando AST del código fuente..."):
                    ast_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "14_ast_scan.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(ast_res["stdout"] or ast_res["stderr"])
            
            if st.button("🚧 AST Exception Guard", use_container_width=True):
                with st.spinner("Verificando excepciones de seguridad en AST..."):
                    ast_guard = PRODUCTION_READY / "security-audit" / "ast_exception_guard.py"
                    res = run_cli_tool([sys.executable, str(ast_guard)])
                    st.code(res["stdout"] or res["stderr"])
                    
            st.subheader("🌐 Escaneo DAST de APIs")
            if st.button("🚀 Ejecutar Fuzzer de APIs REST", use_container_width=True):
                with st.spinner("Lanzando ataques de Fuzzing..."):
                    fuzz_res = run_cli_tool([sys.executable, str(SAST_DAST_DIR / "dast_api_fuzzer.py")])
                    st.code(fuzz_res["stdout"] or fuzz_res["stderr"])
                    
            st.subheader("🔐 Auditoría Control de Acceso (OWASP)")
            if st.button("🔎 Auditar OWASP Access Control", use_container_width=True):
                with st.spinner("Auditando controles de acceso OWASP A01..."):
                    owasp_res = run_cli_tool([sys.executable, str(SAST_DAST_DIR / "owasp_access_control_auditor.py")])
                    st.code(owasp_res["stdout"] or owasp_res["stderr"])

        with col2:
            st.subheader("🚨 Catálogo de Explotación CISA (KEV)")
            if st.button("🔎 Buscar vulnerabilidades activas (KEV)", use_container_width=True):
                with st.spinner("Cruzando SBOM con CISA KEV..."):
                    cisa_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "03_check_cisa_kev.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(cisa_res["stdout"] or cisa_res["stderr"])
            
            if st.button("🚧 CISA KEV Gate (Bloqueo CI/CD)", use_container_width=True, type="primary"):
                with st.spinner("Verificando KEV Gate..."):
                    kev_gate = PRODUCTION_READY / "security-audit" / "cisa_kev_gate.py"
                    res = run_cli_tool([sys.executable, str(kev_gate)])
                    st.code(res["stdout"] or res["stderr"])
                    
            st.subheader("🔗 Cadena de Suministro VEX (NIS2)")
            if st.button("➕ Agregar Advisories VEX (CRA/NIS2)", use_container_width=True):
                with st.spinner("Agregando Vulnerability Exploitability eXchange..."):
                    vex_res = run_cli_tool([sys.executable, str(SUPPLY_CHAIN_DIR / "nis2_supply_chain_vex_aggregator.py")])
                    st.code(vex_res["stdout"] or vex_res["stderr"])

            st.subheader("📜 Verificación SLSA Dependencies")
            if st.button("🔎 Verificar SLSA Level 3+", use_container_width=True):
                with st.spinner("Comprobando procedencia de dependencias..."):
                    slsa_res = run_cli_tool([sys.executable, str(SUPPLY_CHAIN_DIR / "supply_chain_dependency_checker.py")])
                    st.code(slsa_res["stdout"] or slsa_res["stderr"])