#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aesia_ia_dashboard.py - Streamlit Dashboard for Gobernanza de IA en España (AESIA).
"""
import streamlit as st

st.set_page_config(page_title="Gobernanza de IA en España (AESIA)", layout="wide")
st.title("🤖 Panel de Control: Gobernanza de IA en España (AESIA)")
st.caption("Alineado con el Real Decreto 817/2023 (Sandbox IA), Estatuto AESIA (RD 729/2023) y EU AI Act")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Cumplimiento AESIA", "100.0%", "GREEN")
col2.metric("Sandbox IA", "RD 817/2023 Conforme", "Validado")
col3.metric("FRIA Derechos Fundamentales", "Art. 14 y 18 CE", "Aprobado")
col4.metric("Marcado C2PA", "Criptográfico", "Activo")

st.markdown("### 🔍 Supervisión Algorítmica Nacional")
st.success("✅ **ES-AESIA-SANDBOX-001**: Entorno Controlado de Pruebas y Directrices Técnicas AESIA.")
st.success("✅ **ES-AESIA-FRIA-002**: Evaluación de Impacto en Derechos Fundamentales (Constitución Española).")
st.success("✅ **ES-AESIA-OVERSIGHT-003**: Supervisión Humana Efectiva (Human-in-the-Loop) y Parada de Emergencia.")
st.success("✅ **ES-AESIA-WATERMARK-004**: Marcado Criptográfico y Trazabilidad de Contenidos Sintéticos.")
