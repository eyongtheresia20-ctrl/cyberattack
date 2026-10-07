@echo off
echo ========================================================
echo   CyberGuard Sentinel - Lancement avec Microsoft Edge
echo ========================================================
start "" "msedge.exe" --load-extension="D:\cyberattack\extension" "http://localhost:3000/dashboard"
exit
