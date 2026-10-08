@echo off
chcp 65001 >nul
title CyberGuard SOC - Arret Complet du Systeme

color 0C
echo.
echo ==============================================================
echo    ARRET COMPLET DE LA PLATEFORME CYBERGUARD SOC
echo ==============================================================
echo.

:: 1. Restauration de la configuration reseau de l'Agent
echo [1/3] Restauration des parametres reseau (DNS & Proxy)...
cd /d "%~dp0agent"
python cyberguard_agent.py restore >nul 2>&1
echo       [+] Parametres reseau Windows restaures a l'etat normal.

:: 2. Fermeture des fenetres et libération des ports
echo.
echo [2/3] Fermeture des processus Backend, Frontend et Agent...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ports = @(8000, 3000, 8899, 5353); foreach ($p in $ports) { $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; foreach ($c in $conns) { try { $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; if ($proc) { Stop-Process -Id $proc.Id -Force; Write-Host ('      [+] Port ' + $p + ' libere (PID ' + $proc.Id + ')') } } catch {} } }"

for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":3000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8899 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1

:: Fermer les fenêtres CMD ayant nos titres
taskkill /F /FI "WINDOWTITLE eq CyberGuard Backend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq CyberGuard Frontend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq CyberGuard Agent*" >nul 2>&1

echo.
echo [3/3] Tous les services ont ete arretes avec succes.
echo ==============================================================
echo.
pause
