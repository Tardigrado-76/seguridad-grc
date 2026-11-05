@echo off
chcp 65001 >nul
title QUANTIGRADE GCR - Consola Operativa y Agente CLI
color 0B

echo ===============================================================================
echo                QUANTIGRADE GCR ENTERPRISE CLI (Cero-Docker)
echo       Plataforma Soberana de Cumplimiento Regulatorio y Resiliencia Digital
echo ===============================================================================
echo.

cd /d "%~dp0"

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR CRITICO] Python no esta disponible en el PATH del sistema.
    pause
    exit /b 1
)

python quantigrade_cli.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo [AVISO] La consola finalizo con codigo de salida %ERRORLEVEL%.
    pause
)
