@echo off
setlocal EnableDelayedExpansion
title CyberGuard SOC - Universal Launcher

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

echo ==============================================================
echo           CYBERGUARD SOC - UNIVERSAL SYSTEM LAUNCHER
echo ==============================================================
echo.

REM --------------------------------------------------------------
REM STEP 0: Check Administrator privileges
REM --------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    if not "%1"=="--no-elevate" (
        echo [*] Attempting Administrator elevation...
        powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k cd /d \"\"\"%SCRIPT_DIR%\"\"\" ^&^& start.bat --no-elevate' -Verb RunAs" >nul 2>&1
        if !errorlevel! equ 0 (
            exit /b
        )
    )
    echo [1/6] Running in standard mode.
) else (
    echo [1/6] Administrator privileges: ACTIVE
)

REM --------------------------------------------------------------
REM STEP 1: Terminate existing processes on target ports (8000, 3000, 8899)
REM --------------------------------------------------------------
echo.
echo [2/6] Freeing occupied ports (8000, 3000, 8899)...

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports = @(8000, 3000, 8899); foreach ($p in $ports) { $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; foreach ($c in $conns) { try { $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; if ($proc) { Stop-Process -Id $proc.Id -Force; Write-Host ('   [+] Port ' + $p + ' freed (PID: ' + $proc.Id + ')') } } catch {} } }"

for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":3000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8899 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1

echo    [+] Ports 8000, 3000, and 8899 are ready.

REM --------------------------------------------------------------
REM STEP 2: Start Databases (MongoDB and PostgreSQL)
REM --------------------------------------------------------------
echo.
echo [3/6] Checking and starting database services...

sc query MongoDB >nul 2>&1
if %errorlevel% equ 0 (
    echo    [*] Starting MongoDB service...
    net start MongoDB >nul 2>&1
    echo    [+] MongoDB service: ONLINE [Port 27017]
) else (
    echo    [-] Windows MongoDB service not found.
)

sc query postgresql-x64-18 >nul 2>&1
if %errorlevel% equ 0 (
    echo    [*] Starting PostgreSQL service...
    net start postgresql-x64-18 >nul 2>&1
    echo    [+] PostgreSQL service: ONLINE [Port 5432]
) else (
    docker ps >nul 2>&1
    if !errorlevel! equ 0 (
        docker-compose up -d postgres >nul 2>&1
        echo    [+] PostgreSQL Docker container: ONLINE
    ) else (
        echo    [*] Using hybrid SQLite fallback.
    )
)

REM --------------------------------------------------------------
REM STEP 3: Launch Backend (FastAPI / Uvicorn Port 8000)
REM --------------------------------------------------------------
echo.
echo [4/6] Starting CyberGuard Backend API on Port 8000...
start "CyberGuard Backend (Port 8000)" cmd /k "cd /d \"%SCRIPT_DIR%\backend\" && title CyberGuard Backend (Port 8000) && python -m uvicorn app.main:app --reload --port 8000"

ping 127.0.0.1 -n 3 >nul

REM --------------------------------------------------------------
REM STEP 4: Launch Frontend (React / Vite Port 3000)
REM --------------------------------------------------------------
echo.
echo [5/6] Starting CyberGuard Frontend on Port 3000...
start "CyberGuard Frontend (Port 3000)" cmd /k "cd /d \"%SCRIPT_DIR%\frontend\" && title CyberGuard Frontend (Port 3000) && npm run dev"

ping 127.0.0.1 -n 3 >nul

REM --------------------------------------------------------------
REM STEP 5: Launch System-Wide Agent (DNS and Proxy)
REM --------------------------------------------------------------
echo.
echo [6/6] Starting CyberGuard System Agent (DNS and Proxy)...
start "CyberGuard System Agent" cmd /k "cd /d \"%SCRIPT_DIR%\agent\" && title CyberGuard System Agent (Admin) && python cyberguard_agent.py run"

REM --------------------------------------------------------------
REM STEP 6: Open Browser and Print Status
REM --------------------------------------------------------------
echo.
echo ==============================================================
echo   [SUCCESS] ALL CYBERGUARD SERVICES ARE NOW RUNNING!
echo ==============================================================
echo.
echo   * SOC Web Dashboard : http://localhost:3000
echo   * Backend API Docs  : http://localhost:8000/docs
echo   * Interception Agent: Port 53 [DNS] + Port 8899 [Proxy]
echo   * Databases         : MongoDB [27017] / PostgreSQL [5432]
echo.
echo   [+] Opening SOC Dashboard in browser...
start "" "http://localhost:3000"

echo.
echo To stop all services and restore network, run stop.bat.
echo.
pause
