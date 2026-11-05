import sys
from pathlib import Path

import streamlit as st

from path_registry import (
    CLARA_SUITE,
    CRYPTO_DIR,
    DISA_STIGS,
    DORA_PDF_GEN,
    DORA_SCRIPTS,
    HARDENING_DIR,
    PQC_DIR,
    PRODUCTION_READY,
    REPORTS_DORA,
    ZKP_DIR,
)
from shared_utils import run_cli_tool, run_ps1_tool


def render_tab(tab):
    with tab:
        st.header("🔒 Criptografía, IAM & Hardening")
        st.markdown("Criptografía Post-Cuántica, Autenticación ZKP y Hardening ENS Alto.")
        
        col_sec1, col_sec2 = st.columns(2)
        with col_sec1:
            st.subheader("🔑 IAM y Autenticación")
            if st.button("🔎 Auditar Privilegios IAM", use_container_width=True):
                with st.spinner("Auditando asignaciones IAM y control de acceso..."):
                    iam_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "07_iam_privilege_auditor.py"), "--output-dir", str(REPORTS_DORA)])
                    st.code(iam_res["stdout"] or iam_res["stderr"])
            
            if st.button("🛡️ Iniciar Gateway ZKP (Zero-Knowledge Proof)", use_container_width=True):
                with st.spinner("Arrancando Auth Gateway NIST 800-63C..."):
                    zkp_res = run_cli_tool([sys.executable, str(ZKP_DIR / "zero_knowledge_proof_auth_gateway.py")])
                    st.code(zkp_res["stdout"] or zkp_res["stderr"])
                    
            st.markdown("**Generación de Certificados**")
            if st.button("📜 Generar Certificados mTLS Zero Trust", use_container_width=True):
                with st.spinner("Generando certificados mTLS (ECDSA P-384)..."):
                    mtls_res = run_cli_tool([sys.executable, str(PRODUCTION_READY / "security-audit" / "generate_mtls_certs.py")])
                    st.code(mtls_res["stdout"] or mtls_res["stderr"])
            
            if st.button("📜 Generar Certificados Dev TLS", use_container_width=True):
                with st.spinner("Generando certificados TLS para desarrollo..."):
                    dev_tls_res = run_cli_tool([sys.executable, str(PRODUCTION_READY / "security-audit" / "generate_dev_certs.py")])
                    st.code(dev_tls_res["stdout"] or dev_tls_res["stderr"])

            st.subheader("🔗 Inmutabilidad y Logs")
            if st.button("📌 Verificar Logs (Merkle Trees)", use_container_width=True):
                with st.spinner("Calculando hashes SHA-256..."):
                    sample_log = str(Path(REPORTS_DORA) / "test_audit.log")
                    run_cli_tool([sys.executable, str(DORA_SCRIPTS / "20_verify_log_immutability.py"), "--create-sample-log", sample_log, "--output-dir", str(REPORTS_DORA)])
                    log_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "20_verify_log_immutability.py"), "--log-file", sample_log, "--output-dir", str(REPORTS_DORA)])
                    st.code(log_res["stdout"] or log_res["stderr"])
            
            st.subheader("🛡️ Hardening Kernel & SO")
            if st.button("🔎 Auditar Kernel Hardening (DISA/CIS)", use_container_width=True):
                with st.spinner("Comprobando sysctl y protecciones..."):
                    ker_res = run_cli_tool([sys.executable, str(HARDENING_DIR / "ip_pe_kernel_hardening_auditor.py")])
                    st.code(ker_res["stdout"] or ker_res["stderr"])

            st.markdown("**Aplicación de Políticas (PowerShell)**")
            if st.button("⚠️ Ejecutar ENS Alto Hardening (CLARA)", use_container_width=True, type="primary"):
                st.warning("Se requieren permisos de Administrador para aplicar CLARA.")
                with st.spinner("Aplicando políticas ENS Alto..."):
                    clara_res = run_ps1_tool(str(CLARA_SUITE / "CLARAfix_ALTO.ps1"))
                    st.code(clara_res["stdout"] or clara_res["stderr"])
                    
            if st.button("⚠️ Ejecutar Hardening DISA STIG", use_container_width=True, type="primary"):
                st.warning("Aplicando configuraciones de seguridad DISA STIG...")
                with st.spinner("Modificando políticas de sistema..."):
                    disa_res = run_ps1_tool(str(DISA_STIGS / "disa_stig_hardening.ps1"))
                    st.code(disa_res["stdout"] or disa_res["stderr"])

        with col_sec2:
            st.subheader("🔐 Criptografía Post-Cuántica (PQC)")
            if st.button("🔎 Auditoría Agilidad Criptográfica PQC", use_container_width=True):
                with st.spinner("Buscando criptografía débil (RSA, ECC)..."):
                    pqc_agil_res = run_cli_tool([sys.executable, str(PQC_DIR / "pqc_crypto_agility_manager.py")])
                    st.code(pqc_agil_res["stdout"] or pqc_agil_res["stderr"])
            if st.button("📌 Verificador TLS Híbrido PQC", use_container_width=True):
                with st.spinner("Verificando ML-KEM + ML-DSA..."):
                    pqc_tls_res = run_cli_tool([sys.executable, str(PQC_DIR / "pqc_hybrid_tls_verifier.py")])
                    st.code(pqc_tls_res["stdout"] or pqc_tls_res["stderr"])
            if st.button("📝 Firmador PQC Git Commits", use_container_width=True):
                with st.spinner("Firmando con ML-DSA FIPS 204..."):
                    pqc_git_res = run_cli_tool([sys.executable, str(PQC_DIR / "fips_204_mldsa_git_commit_signer.py")])
                    st.code(pqc_git_res["stdout"] or pqc_git_res["stderr"])
            
            st.subheader("🔑 FIPS y RNG")
            if st.button("🔎 Auditor FIPS 140-3 (Zeroización)", use_container_width=True):
                with st.spinner("Comprobando borrado seguro en memoria..."):
                    fips_res = run_cli_tool([sys.executable, str(CRYPTO_DIR / "fips_140_3_zeroization_auditor.py")])
                    st.code(fips_res["stdout"] or fips_res["stderr"])
            if st.button("📊 Monitor de Entropía RNG", use_container_width=True):
                with st.spinner("Calculando entropía del sistema..."):
                    rng_res = run_cli_tool([sys.executable, str(CRYPTO_DIR / "rng_entropy_monitor.py")])
                    st.code(rng_res["stdout"] or rng_res["stderr"])

            st.subheader("💾 Backups y Resiliencia")
            if st.button("🛡️ Backup Cifrado AES-256-GCM", use_container_width=True):
                with st.spinner("Creando snapshot cifrado NIST 800-88..."):
                    bk_res = run_cli_tool([sys.executable, str(DORA_SCRIPTS / "12_bunker_secure_backup.py"), "--generate-demo", "--output-dir", str(REPORTS_DORA)])
                    st.code(bk_res["stdout"] or bk_res["stderr"])
            if st.button("🔎 Auditar Políticas de Retención WORM", use_container_width=True):
                with st.spinner("Verificando inmutabilidad WORM de backups..."):
                    worm_res = run_cli_tool([sys.executable, str(PRODUCTION_READY / "backup-integrity" / "bunker_backups_hardening.py")])
                    st.code(worm_res["stdout"] or worm_res["stderr"])
                    
            st.subheader("📑 Propuestas y Contratos")
            if st.button("📄 Generar Presupuesto TAVILGA PDF", use_container_width=True):
                with st.spinner("Generando documento PDF..."):
                    pdf_res = run_cli_tool([sys.executable, str(DORA_PDF_GEN)])
                    st.code(pdf_res["stdout"] or pdf_res["stderr"])
            if st.button("📄 Generar Presupuesto DOCX Editable", use_container_width=True):
                with st.spinner("Generando documento DOCX..."):
                    docx_res = run_cli_tool([sys.executable, str(PRODUCTION_READY / "doc-generators" / "generate_budget_docx.py")])
                    st.code(docx_res["stdout"] or docx_res["stderr"])