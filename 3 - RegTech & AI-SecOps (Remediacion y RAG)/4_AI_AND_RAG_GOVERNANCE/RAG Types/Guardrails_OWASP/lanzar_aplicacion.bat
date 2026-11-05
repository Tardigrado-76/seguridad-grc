@echo off
title Lanzando RAG Regulado...
echo Iniciando el entorno virtual y cargando la aplicacion RAG Regulado...
echo.

:: Verifica si existe el entorno virtual
if not exist ".venv\Scripts\streamlit.exe" (
    echo [ERROR] No se ha encontrado el entorno virtual o streamlit no esta instalado.
    echo Asegurate de ejecutar este script desde la carpeta Guardrails_OWASP.
    pause
    exit /b
)

:: Ejecuta streamlit a través del entorno virtual local
".venv\Scripts\streamlit.exe" run Rag_Regulado.py

pause
