import datetime
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

import streamlit as st
import streamlit.web.cli as stcli

if __name__ == "__main__":
    if not st.runtime.exists():
        sys.argv = ["streamlit", "run", sys.argv[0]]
        sys.exit(stcli.main())

from dora_pdf_generator import DEFAULT_REPORTS_DIR, generate_report

# -----------------------------------------------------------------------------
# Page Configuration & Brand
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Quantigrade - DORA & Resiliency Compliance Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Locate logo
LOGO_CANDIDATES = [
    Path(__file__).parent / "Quantigrade.jpg",
    Path(r"E:\PROYECTOS IA\Quantigrade.jpg"),
    Path(__file__).parent / "quantigrade.jpg",
]
logo_path = next((p for p in LOGO_CANDIDATES if p.exists()), None)

with st.sidebar:
    if logo_path:
        st.image(str(logo_path), use_container_width=True)
    else:
        st.title("🛡️ Quantigrade")
    
    st.markdown("### **DORA & Resiliency Suite**")
    st.caption("Marco Integral de Cumplimiento Regulatorio (DORA / NIS2 / ENS Alto)")
    st.divider()
    
    current_dir = Path(__file__).parent.resolve()
    project_path = st.text_input("📁 Directorio Objetivo:", value=str(current_dir))
    
    st.markdown("#### 📊 Métricas Rápidas")
    st.metric(label="Normativas", value="DORA / ENS / NIS2")
    st.metric(label="Modo de Ejecución", value="Zero-Trust HITL")
    st.divider()
    st.caption(f"Directorio de Reportes:\n`{DEFAULT_REPORTS_DIR}`")

# Main Header
current_date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
current_year = datetime.datetime.now(datetime.timezone.utc).year

col_title, col_status = st.columns([3, 1])
with col_title:
    st.title("🛡️ Quantigrade | DORA Compliance & Security Hub")
    st.markdown("Plataforma empresarial de auditoría continua, gestión de riesgos TIC, clasificación de incidentes y resiliencia operacional.")
with col_status:
    st.info(f"📅 **{current_date_str} (UTC)**\n⚡ Estado: **Operativo**")

st.write("---")

# -----------------------------------------------------------------------------
# Tabs Navigation
# -----------------------------------------------------------------------------
tab_audit, tab_roi, tab_incident, tab_resilience, tab_crypto = st.tabs([
    "🔍 1. Auditoría de Código & Supply Chain",
    "🏢 2. Proveedores TIC & RoI",
    "🚨 3. Gestión de Incidentes & ANC",
    "⚡ 4. Pruebas de Resiliencia & Caos",
    "🔐 5. Criptografía, IAM & Hardening"
])

# Helper for executing CLI tools
def run_cli_tool(cmd_list: list[str], timeout: int = 120) -> dict[str, Any]:
    try:
        res = subprocess.run(  # nosec B603
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(Path(__file__).parent)
        )
        return {
            "returncode": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "success": res.returncode == 0
        }
    except (subprocess.SubprocessError, OSError) as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "success": False
        }

# =============================================================================
# TAB 1: Auditoría de Código y Cadena de Suministro
# =============================================================================
with tab_audit:
    st.header("🔍 Auditoría Estática de Código y Cadena de Suministro")
    st.markdown("Ejecución combinada de **Code Doctor** (Ruff, Bandit, Mypy), **AST Scan**, **CISA KEV** y generador de **SBOM CycloneDX**.")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        run_full_audit = st.button("🚀 Ejecutar Auditoría Completa", type="primary", use_container_width=True)
    with col2:
        run_cisa_btn = st.button("🛡️ Escaneo CISA KEV", use_container_width=True)
    with col3:
        run_sbom_btn = st.button("📦 Generar SBOM CycloneDX 1.6", use_container_width=True)

    if "audit_results" not in st.session_state:
        st.session_state.audit_results = None

    if run_full_audit:
        if not os.path.exists(project_path):
            st.error("El directorio del proyecto no existe.")
        else:
            with st.spinner("Ejecutando suite de auditoría estática y seguridad..."):
                ruff_res = run_cli_tool([sys.executable, "-m", "ruff", "check", project_path])
                bandit_res = run_cli_tool([sys.executable, "-m", "bandit", "-r", project_path])
                ast_res = run_cli_tool([sys.executable, "14_ast_scan.py", "--path", project_path, "--output-dir", str(DEFAULT_REPORTS_DIR)])
                
                has_issues = (not ruff_res["success"]) or (not bandit_res["success"])
                st.session_state.audit_results = {
                    "ruff": ruff_res,
                    "bandit": bandit_res,
                    "ast": ast_res,
                    "has_issues": has_issues
                }

    if st.session_state.audit_results:
        res = st.session_state.audit_results
        st.subheader("Resultados de la Auditoría")
        
        if res["has_issues"]:
            st.warning("⚠️ Se detectaron vulnerabilidades o advertencias de calidad de código.")
        else:
            st.success("✅ Código 100% conforme con las normativas y mejores prácticas.")
            
        with st.expander("📋 Logs de Ruff (Linter & Formatting)", expanded=True):
            st.code(res["ruff"]["stdout"] or res["ruff"]["stderr"] or "Sin incidencias detectadas.")
            if (not res["ruff"]["success"]) and st.button("🔧 Aplicar Auto-Fix (Ruff --fix)"):
                with st.spinner("Aplicando remediaciones automáticas..."):
                    run_cli_tool([sys.executable, "-m", "ruff", "check", "--fix", project_path])
                    st.success("Auto-Fix aplicado con éxito. Re-ejecuta la auditoría para verificar.")

        with st.expander("🛡️ Logs de Bandit (Seguridad en Código Python)", expanded=True):
            st.code(res["bandit"]["stdout"] or res["bandit"]["stderr"] or "Sin alertas de seguridad.")

        with st.expander("🌳 Análisis AST de Dependencias (14_ast_scan.py)", expanded=False):
            st.code(res["ast"]["stdout"] or res["ast"]["stderr"] or "Escaneo AST completado.")

        st.divider()
        st.subheader("📄 Generación de Informe Formal")
        if st.button("Generar Informe PDF Oficial DORA"):
            errors = []
            if res["has_issues"]:
                errors.append("Se detectaron desalineaciones en la auditoría de código estático (Ruff/Bandit).")
            pdf_path = generate_report(project_path, errors)
            st.success(f"Informe guardado en: `{pdf_path}`")
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="⬇️ Descargar Informe PDF",
                    data=f,
                    file_name=os.path.basename(pdf_path),
                    mime="application/pdf"
                )

    if run_cisa_btn:
        with st.spinner("Consultando catálogo en vivo de CISA KEV..."):
            cisa_res = run_cli_tool([sys.executable, "03_check_cisa_kev.py", "--output-dir", str(DEFAULT_REPORTS_DIR)])
            st.subheader("🛡️ Resultado CISA KEV (Known Exploited Vulnerabilities)")
            st.code(cisa_res["stdout"] or cisa_res["stderr"])

    if run_sbom_btn:
        with st.spinner("Generando y firmando SBOM CycloneDX 1.6..."):
            sbom_res = run_cli_tool([sys.executable, "01_generate_sbom.py", "--path", project_path, "--output-dir", str(DEFAULT_REPORTS_DIR)])
            st.subheader("📦 Resultado SBOM CycloneDX")
            st.code(sbom_res["stdout"] or sbom_res["stderr"])
            st.success(f"Archivos SBOM guardados en `{DEFAULT_REPORTS_DIR}`")

# =============================================================================
# TAB 2: Proveedores TIC y RoI
# =============================================================================
with tab_roi:
    st.header("🏢 Gestión del Riesgo de Terceros TIC & Registro de Información (RoI)")
    st.markdown("Cumplimiento **DORA Artículos 28 a 44** y plantillas **ITS EBA/ITS/2024/01** (RT.01 a RT.04).")
    
    col_roi_1, col_roi_2 = st.columns(2)
    with col_roi_1:
        if st.button("📑 Generar Registro de Información DORA (Demo RoI)", use_container_width=True):
            with st.spinner("Generando estructuras normalizadas RoI..."):
                roi_res = run_cli_tool([sys.executable, "02_generate_dora_roi.py", "--generate-demo", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(roi_res["stdout"] or roi_res["stderr"])
                st.success(f"Estructuras RoI exportadas a `{DEFAULT_REPORTS_DIR}`")
                
    with col_roi_2:
        if st.button("🔍 Auditar Concentración de Proveedores TIC", use_container_width=True):
            with st.spinner("Evaluando concentración de riesgo y SLAs..."):
                tpr_res = run_cli_tool([sys.executable, "dora_ict_third_party_risk_auditor.py", "--target-dir", project_path])
                st.code(tpr_res["stdout"] or tpr_res["stderr"])

# =============================================================================
# TAB 3: Gestión de Incidentes TIC y Notificación ANC
# =============================================================================
with tab_incident:
    st.header("🚨 Gestión, Clasificación y Notificación de Incidentes TIC Mayores")
    st.markdown("Cumplimiento **DORA Artículos 17 a 23** y criterios regulatorios **RTS EBA/RTS/2024/02**.")
    
    st.subheader("1. Calculadora de Clasificación de Incidentes Mayores (Art. 18)")
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
            st.selectbox("Impacto en Integridad/Confidencialidad de Datos:", ["Bajo / Sin Brecha", "Medio", "Alto / Datos Críticos Comprometidos"])
            
        submit_classify = st.form_submit_button("⚖️ Clasificar Incidente según DORA", use_container_width=True)

    if submit_classify:
        with st.spinner("Evaluando umbrales regulatorios de RTS EBA..."):
            cmd = [
                sys.executable, "21_dora_incident_classifier.py",
                "--clients-affected", str(clients_affected),
                "--downtime-hours", str(downtime_hours),
                "--economic-loss", str(economic_loss),
                "--eu-countries", str(eu_countries),
                "--output-dir", str(DEFAULT_REPORTS_DIR)
            ]
            if critical_service:
                cmd.append("--critical-service")
            
            clf_res = run_cli_tool(cmd)
            st.subheader("Resultado de la Clasificación:")
            st.code(clf_res["stdout"] or clf_res["stderr"])

    st.divider()
    st.subheader("2. Generador de Notificación Regulatoria ANC (Art. 19 & 20)")
    col_not1, col_not2, col_not3 = st.columns(3)
    with col_not1:
        if st.button("📢 Notificación Inicial (Plazo 2h)", use_container_width=True):
            with st.spinner("Generando plantilla de alerta inicial..."):
                res_init = run_cli_tool([sys.executable, "23_nca_incident_reporter.py", "--phase", "initial", "--incident-id", f"INC-{current_year}-001", "--entity-name", "Entidad Regulada", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(res_init["stdout"] or res_init["stderr"])
    with col_not2:
        if st.button("📊 Informe Intermedio (Plazo 24h)", use_container_width=True):
            with st.spinner("Generando informe de progreso..."):
                res_int = run_cli_tool([sys.executable, "23_nca_incident_reporter.py", "--phase", "intermediate", "--incident-id", f"INC-{current_year}-001", "--root-cause", "Fallo de infraestructura / resiliencia", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(res_int["stdout"] or res_int["stderr"])
    with col_not3:
        if st.button("🏁 Informe Final (Plazo 1 mes)", use_container_width=True):
            with st.spinner("Generando informe final y remediación..."):
                res_fin = run_cli_tool([sys.executable, "23_nca_incident_reporter.py", "--phase", "final", "--incident-id", f"INC-{current_year}-001", "--title", "Informe Final", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(res_fin["stdout"] or res_fin["stderr"])

    st.divider()
    st.subheader("3. Análisis de Causa Raíz (RCA) & Post-Mortem (ISO 27035)")
    if st.button("📑 Generar Plantilla RCA Post-Mortem Oficial", use_container_width=True):
        with st.spinner("Construyendo reporte de post-mortem..."):
            rca_res = run_cli_tool([sys.executable, "rca_postmortem_generator.py", "--output-dir", str(DEFAULT_REPORTS_DIR)])
            st.code(rca_res["stdout"] or rca_res["stderr"])

# =============================================================================
# TAB 4: Pruebas de Resiliencia, Caos y Salida Cloud
# =============================================================================
with tab_resilience:
    st.header("⚡ Pruebas de Resiliencia Digital, TLPT y Salida Cloud")
    st.markdown("Validación de **DORA Artículos 25 y 26** (Pruebas avanzadas de resiliencia operativa y Threat-Led Penetration Testing).")
    
    col_res1, col_res2 = st.columns(2)
    with col_res1:
        st.subheader("🌐 Estrategia de Salida Cloud (Art. 28.8)")
        if st.button("🧪 Simular Estrategia de Salida (Dry-Run RTO/RPO)", use_container_width=True):
            with st.spinner("Simulando migración de contingencia y validación de RTO/RPO..."):
                exit_res = run_cli_tool([sys.executable, "16_cloud_exit_strategy_test.py", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(exit_res["stdout"] or exit_res["stderr"])
                
        st.subheader("💥 Simulación de Estrés y Ataques DDoS (Art. 26)")
        if st.button("🔥 Ejecutar Test de Estrés (Dry-Run)", use_container_width=True):
            with st.spinner("Evaluando respuesta de WAF y Rate-Limiting..."):
                ddos_res = run_cli_tool([sys.executable, "17_ddos_simulator.py", "--target-url", "http://127.0.0.1:8000/health", "--dry-run", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(ddos_res["stdout"] or ddos_res["stderr"])

    with col_res2:
        st.subheader("🎯 Métricas TLPT (TIBER-EU / MTTD & MTTR)")
        if st.button("📊 Recopilar Evidencias TLPT", use_container_width=True):
            with st.spinner("Calculando tiempos medios de detección y respuesta..."):
                tlpt_res = run_cli_tool([sys.executable, "18_tlpt_evidence_collector.py", "--simulate-exercise", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(tlpt_res["stdout"] or tlpt_res["stderr"])
                
        st.subheader("🔄 Conmutación por Error ante Desastres (Failover Drill)")
        if st.button("⚡ Simular Failover Automatizado", use_container_width=True):
            with st.spinner("Verificando conmutación a nodo secundario..."):
                failover_res = run_cli_tool([sys.executable, "dora_automated_failover_drill.py", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(failover_res["stdout"] or failover_res["stderr"])

# =============================================================================
# TAB 5: Criptografía, Identidad y Hardening
# =============================================================================
with tab_crypto:
    st.header("🔐 Criptografía, Auditoría IAM, Inmutabilidad y Hardening")
    st.markdown("Componentes avanzados y opcionales para máxima robustez técnica (FIPS 203/204/205, ENS Alto, Zero-Trust).")
    
    col_sec1, col_sec2 = st.columns(2)
    with col_sec1:
        st.subheader("👤 Auditoría de Identidad & Hiper-privilegios IAM")
        if st.button("🔍 Auditar Privilegios y Cuentas Huérfanas", use_container_width=True):
            with st.spinner("Auditando asignaciones IAM y control de acceso..."):
                iam_res = run_cli_tool([sys.executable, "07_iam_privilege_auditor.py", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(iam_res["stdout"] or iam_res["stderr"])

        st.subheader("📜 Inmutabilidad de Logs (Merkle Trees)")
        if st.button("🌳 Verificar Integridad Criptográfica de Logs", use_container_width=True):
            with st.spinner("Calculando árbol de Merkle y hashes SHA-256..."):
                sample_log = str(Path(DEFAULT_REPORTS_DIR) / "test_audit.log")
                run_cli_tool([sys.executable, "20_verify_log_immutability.py", "--create-sample-log", sample_log, "--output-dir", str(DEFAULT_REPORTS_DIR)])
                log_res = run_cli_tool([sys.executable, "20_verify_log_immutability.py", "--log-file", sample_log, "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(log_res["stdout"] or log_res["stderr"])
                
        st.subheader("💓 Latido y Telemetría Criptográfica (Heartbeat)")
        if st.button("📡 Comprobar Estado de Salud del Nodo", use_container_width=True):
            with st.spinner("Validando firma HMAC-SHA256..."):
                hb_res = run_cli_tool([sys.executable, "19_heartbeat.py", "--check-once", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(hb_res["stdout"] or hb_res["stderr"])

    with col_sec2:
        st.subheader("🔒 Certificados TLS 1.3 y Criptografía PQC")
        if st.button("🔐 Auditar Configuración Criptográfica TLS / PQC", use_container_width=True):
            with st.spinner("Verificando suite criptográfica..."):
                tls_res = run_cli_tool([sys.executable, "10_tls_config.py", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(tls_res["stdout"] or tls_res["stderr"])

        st.subheader("💾 Copias de Seguridad Cifradas AES-256-GCM")
        if st.button("📦 Generar Backup Seguro de Demostración", use_container_width=True):
            with st.spinner("Creando snapshot cifrado y sanitizado NIST 800-88..."):
                bk_res = run_cli_tool([sys.executable, "12_bunker_secure_backup.py", "--generate-demo", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(bk_res["stdout"] or bk_res["stderr"])

        st.subheader("⚓ Git Security Pre-Commit Hooks")
        if st.button("🛡️ Instalar Git Hooks Locales", use_container_width=True):
            with st.spinner("Configurando hooks de seguridad..."):
                hook_res = run_cli_tool([sys.executable, "06_setup_git_hooks.py", "--output-dir", str(DEFAULT_REPORTS_DIR)])
                st.code(hook_res["stdout"] or hook_res["stderr"])

        st.subheader("💼 Propuesta Económica y Presupuesto")
        if st.button("📑 Generar Presupuesto DORA (PDF)", use_container_width=True):
            with st.spinner("Generando propuesta estratégica..."):
                bud_res = run_cli_tool([sys.executable, "generate_budget_pdf.py"])
                st.code(bud_res["stdout"] or bud_res["stderr"])
