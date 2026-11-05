import sys

import streamlit as st

from path_registry import (
    COMPLIANCE_MANAGER,
    ENS_AUDITORS,
    ORCHESTRATOR_CLI,
    REPORTS_DIR,
)
from shared_utils import run_cli_tool


def render_tab(tab):
    with tab:
        st.header("🌍 Auditoría Multi-Normativa y GRC")
        st.markdown("Consola Unificada GRC: Orquestación, Reporting CISO y Generación de Guías.")
        
        st.subheader("⚙️ Orquestador Central de Cumplimiento")
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown("**1. Seleccione Normativas**")
            audit_dora = st.checkbox("DORA", value=True)
            audit_ens = st.checkbox("ENS Alta", value=True)
            audit_nis2 = st.checkbox("NIS2", value=True)
            audit_rgpd = st.checkbox("RGPD", value=True)
            audit_cra = st.checkbox("CRA", value=True)
            
            st.divider()
            st.markdown("**2. Seleccione Sector**")
            sector = st.selectbox(
                "Sector de Aplicación",
                ["Tecnológico", "Banca y Finanzas", "Salud", "Administración Pública", "Energía", "Telecomunicaciones"]
            )
            
        with col2:
            st.info("La auditoría completa evaluará todos los controles seleccionados en el entorno actual.")
            
            if st.button("🚀 Ejecutar Auditoría Global", use_container_width=True, type="primary"):
                with st.spinner(f"Inicializando motores de evaluación para el sector {sector}..."):
                    cmd = [sys.executable, str(ORCHESTRATOR_CLI)]
                    
                    if audit_dora and audit_ens and audit_nis2 and audit_rgpd and audit_cra:
                        cmd.extend(["--mode", "full"])
                    else:
                        cmd.append("--modules")
                        modules = []
                        if audit_dora: modules.append("dora")
                        if audit_ens: modules.append("ens")
                        if audit_nis2: modules.append("nis2")
                        if audit_rgpd: modules.append("gdpr")
                        if audit_cra: modules.append("cra")
                        cmd.append(",".join(modules))
                        
                    res = run_cli_tool(cmd, timeout=300)
                    st.success("Auditoría Finalizada")
                    st.code(res["stdout"] or res["stderr"])
                    st.markdown(f"**Reportes de Auditoría** guardados en: `{REPORTS_DIR}`")
                    
            st.divider()
            st.markdown("**Reporting y GRC**")
            
            ciso_btn = st.button("📊 Generar Reporte Ejecutivo CISO", use_container_width=True)
            if ciso_btn:
                ciso_script = COMPLIANCE_MANAGER / "src" / "reporters" / "executive_ciso_summary.py"
                with st.spinner("Compilando métricas ejecutivas..."):
                    res = run_cli_tool([sys.executable, str(ciso_script)])
                    st.code(res["stdout"] or res["stderr"] or "Reporte CISO generado exitosamente.")
            
            guide_btn = st.button("📘 Generar Guía PDF Consolidada", use_container_width=True)
            if guide_btn:
                st.info("Generación de guía PDF completa en proceso. Consulte el directorio REPORTS.")
                # Aquí se integraría la llamada al generador PDF si existe.
                
        st.divider()
        st.subheader("🔍 Controles Específicos Adicionales")
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            if st.button("🔎 Auditar Políticas de Acceso ENS (op.acc.1)"):
                with st.spinner("Auditando..."):
                    res = run_cli_tool([sys.executable, str(ENS_AUDITORS / "ens_access_policy_auditor.py")])
                    st.code(res["stdout"] or res["stderr"])
        with col_c2:
            if st.button("🛡️ Auditar Gestión de Parches ENS (op.exp.4)"):
                with st.spinner("Auditando..."):
                    res = run_cli_tool([sys.executable, str(ENS_AUDITORS / "ens_vulnerability_and_patch_auditor.py")])
                    st.code(res["stdout"] or res["stderr"])