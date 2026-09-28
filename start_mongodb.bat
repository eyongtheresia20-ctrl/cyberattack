@echo off
title Demarrage MongoDB Server CyberGuard
color 0A
echo =======================================================
echo    DEMARRAGE DU SERVICE MONGODB (CYBERGUARD)
echo =======================================================
echo.
echo Demarrage en cours du service MongoDB...
net start MongoDB
echo.
if %errorlevel% equ 0 (
    echo =======================================================
    echo  [SUCCES] Le serveur MongoDB est maintenant EN LIGNE !
    echo  Vous pouvez retourner sur MongoDB Compass et cliquer
    echo  sur "Find" ou "Reset".
    echo =======================================================
) else (
    echo =======================================================
    echo  [ATTENTION] L'acces a ete refuse.
    echo  Faites un CLIC DROIT sur ce fichier start_mongodb.bat
    echo  et choisissez : "Executer en tant qu'administrateur" !
    echo =======================================================
)
echo.
pause
