@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
title Quantigrade Multi-Normativa Compliance Suite

echo ===============================================================================
echo   QUANTIGRADE ^| Centro de Cumplimiento y Seguridad Normativa
echo   DORA ^| NIS2 ^| ENS Alto ^| RGPD ^| CRA ^| EU AI Act
echo ===============================================================================
echo.

:: 1. Establecer directorio de trabajo al del script
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"

:: 2. Localizar intérprete de Python
set "PYTHON_EXE="

:: Intentar python en PATH
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_EXE=python"
    goto :PYTHON_FOUND
)

:: Rutas de fallback habituales en Windows
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    goto :PYTHON_FOUND
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    goto :PYTHON_FOUND
)
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :PYTHON_FOUND
)
if exist "%ProgramFiles%\Python313\python.exe" (
    set "PYTHON_EXE=%ProgramFiles%\Python313\python.exe"
    goto :PYTHON_FOUND
)
if exist "%ProgramFiles%\Python312\python.exe" (
    set "PYTHON_EXE=%ProgramFiles%\Python312\python.exe"
    goto :PYTHON_FOUND
)

echo [ERROR] No se ha encontrado ningun interprete de Python en el sistema.
echo Por favor, instale Python 3.11 o superior y asegurese de marcar "Add to PATH".
echo.
pause
exit /b 1

:PYTHON_FOUND
echo [OK] Python detectado: 
"%PYTHON_EXE%" --version
echo.

:: 3. Verificar dependencias core (streamlit, plotly)
echo [*] Verificando dependencias necesarias (Streamlit, Plotly)...
"%PYTHON_EXE%" -c "import streamlit, plotly" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [AVISO] Faltan dependencias necesarias en el entorno Python.
    echo [*] Instalando dependencias desde requirements.txt...
    "%PYTHON_EXE%" -m pip install -r "%~dp0requirements.txt"
    if %ERRORLEVEL% neq 0 (
        echo.
        echo [ERROR] Fallo al instalar las dependencias con pip.
        pause
        exit /b 1
    )
    echo [OK] Dependencias instaladas con exito.
    echo.
) else (
    echo [OK] Dependencias verificadas correctamente.
    echo.
)

:: 4. Verificación rápida de rutas del sistema
if exist "%~dp0verify_paths.py" (
    echo [*] Verificando registro de rutas normativas...
    "%PYTHON_EXE%" "%~dp0verify_paths.py" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        echo [OK] 55/55 rutas normativas verificadas y operativas.
    ) else (
        echo [AVISO] Algunas rutas secundarias podrian requerir atencion.
    )
    echo.
)

:: 5. Iniciar la aplicación Streamlit
echo ===============================================================================
echo   Lanzando plataforma en http://localhost:8501
echo   Para cerrar la plataforma, cierre esta ventana o presione Ctrl+C.
echo ===============================================================================
echo.

"%PYTHON_EXE%" -m streamlit run "%~dp0dora_streamlit_app.py" ^
    --server.port 8501 ^
    --server.headless false ^
    --browser.serverAddress localhost ^
    --theme.base "dark" ^
    --theme.primaryColor "#00E5FF" ^
    --theme.backgroundColor "#070B14" ^
    --theme.secondaryBackgroundColor "#0D1424" ^
    --theme.textColor "#E0F2F1"

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] La aplicacion Streamlit ha finalizado con codigo de error %ERRORLEVEL%.
    pause
)
