@echo off
setlocal EnableDelayedExpansion
title CyberGuard SOC - Stop Services

echo ==============================================================
echo           STOPPING ALL CYBERGUARD SERVICES
echo ==============================================================
echo.

REM 1. Restore network configuration from agent
echo [1/3] Restoring network settings (DNS and Proxy)...
cd /d "%~dp0agent"
python cyberguard_agent.py restore >nul 2>&1
echo       [+] Network settings restored to defaults.

REM 2. Terminate running processes on ports 8000, 3000, 8899
echo.
echo [2/3] Terminating Backend, Frontend, and Agent processes...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports = @(8000, 3000, 8899); foreach ($p in $ports) { $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; foreach ($c in $conns) { try { $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; if ($proc) { Stop-Process -Id $proc.Id -Force; Write-Host ('      [+] Port ' + $p + ' freed (PID ' + $proc.Id + ')') } } catch {} } }"

for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":3000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8899 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1

taskkill /F /FI "WINDOWTITLE eq CyberGuard Backend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq CyberGuard Frontend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq CyberGuard System Agent*" >nul 2>&1

echo.
echo [3/3] All CyberGuard services have been stopped successfully.
echo ==============================================================
echo.
pause
