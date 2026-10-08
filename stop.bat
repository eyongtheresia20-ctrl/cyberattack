@echo off
setlocal
title CyberGuard SOC - Arret Complet

cd /d "%~dp0"
set "ROOT=%CD%"

echo ==============================================================
echo           ARRET COMPLET DE LA PLATEFORME CYBERGUARD SOC
echo ==============================================================
echo.

REM 1. Restauration du reseau
echo [1/3] Restauration des parametres reseau (DNS et Proxy)...
cd /d "%ROOT%\agent"
python cyberguard_agent.py restore >nul 2>&1
echo       [+] Parametres reseau restaures a l'etat normal.

REM 2. Liberation des ports
echo.
echo [2/3] Fermeture des processus Backend, Frontend et Agent...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports = @(8000, 3000, 8899); foreach ($p in $ports) { $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; foreach ($c in $conns) { try { $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; if ($proc) { Stop-Process -Id $proc.Id -Force; Write-Host ('      [+] Port ' + $p + ' libere (PID ' + $proc.Id + ')') } } catch {} } }"

for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":3000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8899 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1

taskkill /F /FI "WINDOWTITLE eq CyberGuard Backend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq CyberGuard Frontend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq CyberGuard System Agent*" >nul 2>&1

echo.
echo [3/3] Tous les services CyberGuard ont ete arretes avec succes.
echo ==============================================================
echo.
pause
