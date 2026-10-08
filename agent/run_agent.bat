@echo off
chcp 65001 >nul
echo ========================================================
echo   CYBERGUARD SOC - LANCEMENT DE L'AGENT SYSTEME
echo ========================================================
echo.

:: Vérifier les privilèges Administrateur
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Élévation des privilèges requise pour configurer le DNS système.
    echo [*] Demande d'élévation Administrateur en cours...
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d \"%~dp0\" && title CyberGuard Agent (Admin) && python cyberguard_agent.py run' -Verb RunAs"
    exit /b
)

title CyberGuard Agent (Admin)
cd /d "%~dp0"
python cyberguard_agent.py run
pause
