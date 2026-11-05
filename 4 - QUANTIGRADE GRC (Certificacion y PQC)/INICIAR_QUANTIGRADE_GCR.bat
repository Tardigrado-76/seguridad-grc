@echo off
title QUANTIGRADE GCR ENTERPRISE MASTER SUITE
color 0B
echo ===============================================================================
echo                QUANTIGRADE GCR ENTERPRISE MASTER SUITE
echo    Plataforma Integral de Gobernanza Continua, Resiliencia y Certificacion
echo                      (19 Marcos Europeos y Espanoles)
echo ===============================================================================
echo.
echo Iniciando servidor Streamlit en puerto 8501...
python -m streamlit run "E:\PROYECTOS IA\GCR\app_quantigrade_gcr_master.py" --server.port 8501 --server.headless false
pause
