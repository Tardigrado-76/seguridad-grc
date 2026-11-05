@echo off
title IT_COMPLIANCE_MANAGER - Bunker Launcher
cd /d "%~dp0"
python "%~dp0orchestrator_cli.py" %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Ocurrio un error en la ejecucion.
    pause
)
