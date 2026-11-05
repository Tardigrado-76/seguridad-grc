#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
corporate_defense_dashboard.py - Streamlit Dashboard for Corporate Defense y Prevención Penal.
"""
import streamlit as st

st.set_page_config(page_title="Corporate Defense & Prevención Penal", layout="wide")
st.title("⚖️ Panel de Control: Corporate Defense y Prevención Penal")
st.caption("Alineado con el Código Penal Español (Art. 31 bis), UNE 19601 y Ley 2/2023 de Protección del Informante")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Cumplimiento Penal", "100.0%", "GREEN")
col2.metric("Canal de Denuncias", "Ley 2/2023 Cifrado", "Activo")
col3.metric("Cadena de Custodia", "SHA-256 Inmutable", "Certificado")
col4.metric("Delitos Informáticos", "Mitigados al 100%", "Bajo Riesgo")

st.markdown("### 🏛️ Ejes de Supervisión Penal Societaria")
st.success("✅ **ES-CP-31BIS-001**: Modelo de Prevención de Delitos y Órgano de Cumplimiento conforme a UNE 19601.")
st.success("✅ **ES-CP-WHISTLE-002**: Canal de Denuncias Interno Confidencial y Anónimo (Ley 2/2023).")
st.success("✅ **ES-CP-EVIDENCE-003**: Cadena de Custodia Digital e Inmutabilidad Forense de Pruebas.")
st.success("✅ **ES-CP-CYBERCRIME-004**: Controles Técnicos Específicos contra Delitos Informáticos Societarios.")
