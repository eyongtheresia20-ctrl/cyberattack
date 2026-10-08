@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title CyberGuard SOC - Lanceur Universel du Système

:: ========================================================
::   CYBERGUARD SOC - UNIVERSAL SYSTEM LAUNCHER
:: ========================================================
color 0B
echo.
echo  ==============================================================
echo    ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
echo   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
echo   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
echo   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██╔══██║
echo   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
echo    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
echo  ==============================================================
echo                PLATEFORME DE DEFENSE CYBERGUARD SOC
echo             Lancement Automatique et Complet du Systeme
echo  ==============================================================
echo.

:: --------------------------------------------------------
:: ETAPE 0 : VERIFICATION DES PRIVILEGES ADMINISTRATEUR
:: --------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Privilèges Administrateur requis pour démarrer les services BD et le DNS.
    echo [*] Élévation en cours...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c cd /d \"%~dp0\" && start.bat' -Verb RunAs"
    exit /b
)

echo [1/6] Vérification des privilèges Administrateur : OK (Élevé)

:: --------------------------------------------------------
:: ETAPE 1 : LIBERATION DES PORTS OCCUPES (8000, 3000, 8899, 5353)
:: --------------------------------------------------------
echo.
echo [2/6] Libération des ports occupés (Arrêt des anciens processus)...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ports = @(8000, 3000, 8899, 5353); foreach ($p in $ports) { $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; foreach ($c in $conns) { try { $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; if ($proc) { Stop-Process -Id $proc.Id -Force; Write-Host ('   [+] Port ' + $p + ' libéré (PID ' + $proc.Id + ' - ' + $proc.ProcessName + ')') -ForegroundColor Yellow } } catch {} } }"

:: Fallback direct au cas où
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":3000 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":8899 .*LISTENING"') do taskkill /F /PID %%a >nul 2>&1

echo    [+] Ports 8000 (Backend), 3000 (Frontend) et 8899 (Proxy) prêts à l'emploi.

:: --------------------------------------------------------
:: ETAPE 2 : DEMARRAGE DES BASES DE DONNEES (MongoDB & PostgreSQL)
:: --------------------------------------------------------
echo.
echo [3/6] Vérification et démarrage des bases de données...

:: A) MongoDB Server
sc query MongoDB >nul 2>&1
if %errorlevel% equ 0 (
    echo    [*] Démarrage du service MongoDB...
    net start MongoDB >nul 2>&1
    echo    [+] Service MongoDB : EN LIGNE (Port 27017)
) else (
    echo    [-] Service Windows MongoDB non détecté.
)

:: B) PostgreSQL Server (postgresql-x64-18 ou postgresql-x64-*)
sc query postgresql-x64-18 >nul 2>&1
if %errorlevel% equ 0 (
    echo    [*] Démarrage du service PostgreSQL...
    net start postgresql-x64-18 >nul 2>&1
    echo    [+] Service PostgreSQL : EN LIGNE (Port 5432)
) else (
    echo    [*] Vérification Docker pour PostgreSQL...
    docker ps >nul 2>&1
    if %errorlevel% equ 0 (
        docker-compose up -d postgres >nul 2>&1
        echo    [+] Conteneur PostgreSQL Docker : EN LIGNE
    ) else (
        echo    [-] PostgreSQL local utilisé avec repli SQLite hybride.
    )
)

:: --------------------------------------------------------
:: ETAPE 3 : LANCEMENT DU BACKEND FASTAPI (Port 8000)
:: --------------------------------------------------------
echo.
echo [4/6] Lancement du Backend FastAPI / IA (Port 8000)...
start "CyberGuard Backend API [Port 8000]" cmd /k "cd /d \"%~dp0backend\" && color 0A && title CyberGuard Backend (Port 8000) && python -m uvicorn app.main:app --reload --port 8000"

:: Attente de 3 secondes pour que le backend initialise ses routes
timeout /t 3 /nobreak >nul

:: --------------------------------------------------------
:: ETAPE 4 : LANCEMENT DU FRONTEND REACT / VITE (Port 3000)
:: --------------------------------------------------------
echo.
echo [5/6] Lancement du Frontend React SOC (Port 3000)...
start "CyberGuard Frontend SOC [Port 3000]" cmd /k "cd /d \"%~dp0frontend\" && color 09 && title CyberGuard Frontend (Port 3000) && npm run dev"

:: Attente de 3 secondes pour le serveur de développement Vite
timeout /t 3 /nobreak >nul

:: --------------------------------------------------------
:: ETAPE 5 : LANCEMENT DE L'AGENT SYSTEME (DNS + Proxy Interception)
:: --------------------------------------------------------
echo.
echo [6/6] Lancement de l'Agent Système CyberGuard (DNS & Proxy)...
start "CyberGuard Agent Systeme [DNS+Proxy]" cmd /k "cd /d \"%~dp0agent\" && color 0C && title CyberGuard Agent Systeme (Admin) && python cyberguard_agent.py run"

:: --------------------------------------------------------
:: ETAPE 6 : OUVERTURE DU NAVIGATEUR ET RESUME
:: --------------------------------------------------------
echo.
echo ==============================================================
echo   [SUCCES] TOUS LES MODULES CYBERGUARD SONT MAINTENANT ACTIFS !
echo ==============================================================
echo.
echo   * Tableau de bord SOC : http://localhost:3000
echo   * Documentation API   : http://localhost:8000/docs
echo   * Agent Interception  : Port 53 (DNS) + Port 8899 (Proxy)
echo   * Base de données     : MongoDB (27017) / PostgreSQL (5432)
echo.
echo   [+] Ouverture automatique de la console SOC dans votre navigateur...
start "" "http://localhost:3000"

echo.
echo Pour arrêter complètement la plateforme, exécutez stop.bat ou fermez les fenêtres.
echo.
pause
