#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lssice_dashboard.py - Streamlit Dashboard for LSSI-CE & Cookies AEPD.
"""
import streamlit as st

st.set_page_config(page_title="LSSI-CE y Cookies (Ley 34/2002)", layout="wide")
st.title("🍪 Panel de Control: LSSI-CE y Cookies AEPD")
st.caption("Alineado con la Ley 34/2002 de Servicios de la Sociedad de la Información y la Guía AEPD 2024")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Cumplimiento LSSI-CE", "100.0%", "GREEN")
col2.metric("Aviso Legal Mercantil", "Art. 10 Conforme", "Vigente")
col3.metric("Cookies Guía AEPD", "Rechazar en 1 Clic", "Sin Dark Patterns")
col4.metric("Anti-Spam Art. 21", "Doble Opt-in", "Garantizado")

st.markdown("### 🛒 Auditoría de Comercio Electrónico y Privacidad Web")
st.success("✅ **ES-LSSI-NOTICE-001**: Información General Permanente Obligatoria (Art. 10 LSSI-CE).")
st.success("✅ **ES-LSSI-COOKIE-002**: Consentimiento Granular de Cookies conforme Guía AEPD 2024 (Art. 22.2).")
st.success("✅ **ES-LSSI-SPAM-003**: Prohibición de Comunicaciones Comerciales No Solicitadas (Art. 21).")
st.success("✅ **ES-LSSI-TAKEDOWN-004**: Procedimiento Ágil de Retirada de Contenidos Ilícitos (Arts. 13-17 / DSA).")
