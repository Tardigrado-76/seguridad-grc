#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lpic_critical_infrastructure_dashboard.py - Streamlit Dashboard for LPIC (Ley 8/2011).
"""
import streamlit as st

st.set_page_config(page_title="Protección de Infraestructuras Críticas (LPIC)", layout="wide")
st.title("🏭 Panel de Control: Protección de Infraestructuras Críticas (LPIC)")
st.caption("Alineado con la Ley 8/2011, Real Decreto 704/2011 y Centro Nacional de Protección de Infraestructuras Críticas (CNPIC)")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Cumplimiento LPIC", "100.0%", "GREEN")
col2.metric("Plan PSO Operador", "Aprobado CNPIC", "Vigente")
col3.metric("Planes PPE Instalación", "100% Implementados", "Activo")
col4.metric("Seguridad OT / Air-Gap", "Aislamiento Total", "Segregado")

st.markdown("### 🛡️ Medidas de Protección Estratégica Nacional")
st.success("✅ **ES-LPIC-PSO-001**: Plan de Seguridad del Operador (PSO) aprobado ante CNPIC.")
st.success("✅ **ES-LPIC-PPE-002**: Planes de Protección Específicos (PPE) por instalación crítica.")
st.success("✅ **ES-LPIC-RSO-003**: Designación oficial del Responsable de Seguridad y Enlace (RSO).")
st.success("✅ **ES-LPIC-AIRGAP-004**: Controles de Aislamiento Físico y Cibernético (Air-Gap y Resiliencia).")
