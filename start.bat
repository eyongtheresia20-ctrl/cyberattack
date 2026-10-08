@echo off
setlocal
title CyberGuard SOC - Universal Launcher

REM Positionnement direct dans le dossier racine du projet
cd /d "%~dp0"
set "ROOT=%CD%"

echo ==============================================================
echo           CYBERGUARD SOC - UNIVERSAL SYSTEM LAUNCHER
echo ==============================================================
echo.

REM --------------------------------------------------------------
REM STEP 0: Check Administrator privileges
REM --------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    if not "%1"=="--elevated" (
        echo [*] Demande d'elevation Administrateur pour la configuration reseau...
        powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -WorkingDirectory '%ROOT%' -ArgumentList '/k start.bat --elevated' -Verb RunAs" >nul 2>&1
        if not errorlevel 1 exit /b
    )
    echo [1/6] Mode utilisateur standard actif.
) else (
    echo [1/6] Privileges Administrateur : ACTIFS
)

REM --------------------------------------------------------------
REM STEP 1: Terminate existing processes on target ports (8000, 3000, 8899)
REM --------------------------------------------------------------
echo.
echo [2/6] Liberation des ports occupes (8000, 3000, 8899)...

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports = @(8000, 3000, 8899); foreach ($p in $ports) { $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; foreach ($c in $conns) { try { $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; if ($proc) { Stop-Process -Id $proc.Id -Force; Write-Host ('   [+] Port ' + $p + ' libere (PID: ' + $proc.Id + ')') } } catch {} } }"

for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":3000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8899 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1

echo    [+] Ports 8000, 3000 et 8899 prets a l'emploi.

REM --------------------------------------------------------------
REM STEP 2: Start Databases (MongoDB and PostgreSQL)
REM --------------------------------------------------------------
echo.
echo [3/6] Verification et demarrage des bases de donnees...

sc query MongoDB >nul 2>&1
if %errorlevel% equ 0 (
    echo    [*] Demarrage du service MongoDB...
    net start MongoDB >nul 2>&1
    echo    [+] Service MongoDB : EN LIGNE [Port 27017]
) else (
    echo    [-] Service Windows MongoDB non detecte.
)

sc query postgresql-x64-18 >nul 2>&1
if %errorlevel% equ 0 (
    echo    [*] Demarrage du service PostgreSQL...
    net start postgresql-x64-18 >nul 2>&1
    echo    [+] Service PostgreSQL : EN LIGNE [Port 5432]
) else (
    docker ps >nul 2>&1
    if not errorlevel 1 (
        docker-compose up -d postgres >nul 2>&1
        echo    [+] Conteneur PostgreSQL Docker : EN LIGNE
    ) else (
        echo    [*] Utilisation du repli hybride SQLite.
    )
)

REM --------------------------------------------------------------
REM STEP 3: Launch Backend (FastAPI / Uvicorn Port 8000)
REM --------------------------------------------------------------
echo.
echo [4/6] Demarrage du Backend FastAPI sur le Port 8000...
start "CyberGuard Backend (Port 8000)" cmd /k "cd /d \"%ROOT%\backend\" && title CyberGuard Backend (Port 8000) && python -m uvicorn app.main:app --reload --port 8000"

ping 127.0.0.1 -n 3 >nul

REM --------------------------------------------------------------
REM STEP 4: Launch Frontend (React / Vite Port 3000)
REM --------------------------------------------------------------
echo.
echo [5/6] Demarrage du Frontend React sur le Port 3000...
start "CyberGuard Frontend (Port 3000)" cmd /k "cd /d \"%ROOT%\frontend\" && title CyberGuard Frontend (Port 3000) && npm run dev"

ping 127.0.0.1 -n 3 >nul

REM --------------------------------------------------------------
REM STEP 5: Launch System-Wide Agent (DNS and Proxy)
REM --------------------------------------------------------------
echo.
echo [6/6] Demarrage de l'Agent Systeme CyberGuard (DNS et Proxy)...
start "CyberGuard System Agent" cmd /k "cd /d \"%ROOT%\agent\" && title CyberGuard System Agent (Admin) && python cyberguard_agent.py run"

REM --------------------------------------------------------------
REM STEP 6: Open Browser and Print Status
REM --------------------------------------------------------------
echo.
echo ==============================================================
echo   [SUCCES] TOUS LES SERVICES CYBERGUARD SONT MAINTENANT ACTIFS
echo ==============================================================
echo.
echo   * Tableau de bord SOC : http://localhost:3000
echo   * Documentation API   : http://localhost:8000/docs
echo   * Agent Interception  : Port 53 [DNS] + Port 8899 [Proxy]
echo   * Bases de donnees    : MongoDB [27017] / PostgreSQL [5432]
echo.
echo   [+] Ouverture du Tableau de bord dans votre navigateur...
start "" "http://localhost:3000"

echo.
echo Pour tout arreter et restaurer le reseau, lancez stop.bat.
echo.
pause
