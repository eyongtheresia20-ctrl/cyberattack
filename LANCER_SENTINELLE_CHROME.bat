@echo off
echo ========================================================
echo   CyberGuard Sentinel - Lancement avec Google Chrome
echo ========================================================
start "" "chrome.exe" --load-extension="D:\cyberattack\extension" "http://localhost:3000/dashboard"
exit
