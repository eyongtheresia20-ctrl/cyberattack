@echo off
chcp 65001 >nul
echo ========================================================
echo   CYBERGUARD SOC - RESTAURATION RESEAU D'URGENCE
echo ========================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Élévation Administrateur requise pour restaurer le DNS.
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d \"%~dp0\" && python cyberguard_agent.py restore && pause' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
python cyberguard_agent.py restore
echo.
pause
