@echo off
setlocal
title AUDIT_CONSOLE - BunkerOS Security Dashboard Launcher
echo ======================================================================
echo   AUDIT_CONSOLE - BunkerOS Security Dashboard Launcher
echo ======================================================================
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_audit_console.ps1" %*
pause
