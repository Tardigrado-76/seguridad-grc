@echo off
:: ============================================================================
:: BunkerOS Auto-Air-Gap Script (Windows)
:: MITRE ATT&CK: T1562.004 - Impair Defenses: Disable or Modify System Firewall
:: Invocado por IntrusionDetectionEngine cuando se supera el umbral de ráfaga.
:: Uso: auto_air_gap.bat <MITRE_ID>
:: ============================================================================
setlocal EnableDelayedExpansion

set TRIGGER_ID=%~1
set TIMESTAMP=%DATE% %TIME%
set LOG_FILE=%~dp0..\logs\air_gap_activations.log

echo [%TIMESTAMP%] T1562.004 - Air-Gap activado por: %TRIGGER_ID% >> "%LOG_FILE%" 2>&1

:: Eliminar regla previa si existe (idemopotente)
netsh advfirewall firewall delete rule name="BUNKER_AIR_GAP_INBOUND" >nul 2>&1
netsh advfirewall firewall delete rule name="BUNKER_AIR_GAP_OUTBOUND" >nul 2>&1

:: Bloquear tráfico entrante
netsh advfirewall firewall add rule ^
    name="BUNKER_AIR_GAP_INBOUND" ^
    dir=in ^
    action=block ^
    protocol=tcp ^
    localport=8000,8010,8443 ^
    enable=yes ^
    description="BunkerOS Auto-Air-Gap T1562.004"

:: Bloquear tráfico saliente
netsh advfirewall firewall add rule ^
    name="BUNKER_AIR_GAP_OUTBOUND" ^
    dir=out ^
    action=block ^
    protocol=tcp ^
    localport=8000,8010,8443 ^
    enable=yes ^
    description="BunkerOS Auto-Air-Gap T1562.004"

echo [%TIMESTAMP%] Air-Gap aplicado. Puertos 8000,8010,8443 bloqueados. >> "%LOG_FILE%" 2>&1
echo [BUNKER AIR-GAP] Aislamiento de red activado correctamente.
exit /b 0
