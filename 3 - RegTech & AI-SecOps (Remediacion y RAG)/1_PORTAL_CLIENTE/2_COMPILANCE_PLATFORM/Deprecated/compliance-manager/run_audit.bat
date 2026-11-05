@echo off
title IT_COMPLIANCE_MANAGER - Motor de Auditoria Automatizada y Gobernanza
cd /d "%~dp0"
echo ================================================================================
echo  INICIANDO IT_COMPLIANCE_MANAGER (Compliance-as-Code Engine)
echo ================================================================================
python "%~dp0orchestrator_cli.py" --interactive
echo.
echo ================================================================================
echo  Proceso finalizado.
echo ================================================================================
pause
