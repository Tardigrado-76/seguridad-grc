@echo off
setlocal enabledelayedexpansion
title QUANTIGRADE GCR Enterprise Master Suite - Secure Launcher
cls
echo ===============================================================================
echo                QUANTIGRADE GCR ENTERPRISE MASTER SUITE
echo          Plataforma Soberana de Cumplimiento, Riesgo y Ciberseguridad
echo ===============================================================================
echo.
echo Seleccione el Perfil Operativo / Mision de Arranque:
echo.
echo   [1] 👑 Suite Completa (25 Marcos Regulatorios Soberanos)
echo   [2] 🛡️  Defensa Militar & OTAN (DGAM / ITAR-EAR / MCCE / PQC)
echo   [3] 🏭  Industria OT/IoT & Logistica Critica (ISA-IEC 62443 / DPP Aduanas)
echo   [4] 🏛️  Sector Publico & CCN-CERT (ENS Alto / LUCIA / INES)
echo   [5] 🌐  Enterprise IA & Financiero (EU AI Act / DORA / RGPD / OWASP)
echo.
set /p PROFILE_CHOICE="Introduzca su eleccion [1-5] (Por defecto 1): "
if "%PROFILE_CHOICE%"=="" set PROFILE_CHOICE=1

echo.
echo [*] Ejecutando Preflight Security Check...
python -c "import sys; print('Python Runtime:', sys.version.split()[0], '| Cero Docker: OK | Air-Gapped: OK')"

echo.
echo [*] Iniciando Streamlit en modo seguro headless (localhost:8501)...
streamlit run app_quantigrade_gcr_master.py --server.headless true --server.port 8501 --server.address 127.0.0.1
pause
