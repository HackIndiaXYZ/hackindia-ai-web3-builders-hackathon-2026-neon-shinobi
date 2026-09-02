@echo off
REM ============================================================
REM ONE-CLICK STARTUP (Simplified — backend ab sab kuch khud karta hai)
REM Ye file "Scan input" folder ke andar honi chahiye.
REM Ab bas backend_server.py chalana hai — wahi apne aap continuous
REM live-capture loop (30-sec cycles) chalata rahega, aur dashboard
REM khud auto-refresh hoke naya data dikhata rahega.
REM ============================================================

cd /d "%~dp0"

echo ============================================
echo   Zero-Trust Dashboard - Auto-Live-Mode
echo ============================================
echo.
echo Backend server start ho raha hai...
echo Ye apne aap har 30 second mein: live-capture -^> risk-engine -^>
echo policy-generator -^> AI-agent, LOOP mein chalata rahega.
echo.
echo Pehla live-data cycle poora hone mein ~30-40 second lagenge.
echo.

start "Zero-Trust Backend (Continuous Live Mode)" cmd /k python3 backend_server.py

echo Backend window khul gayi — usko band mat karna, wahi loop chala raha hai.
echo Dashboard 40 second baad automatically khulega (pehla cycle complete hone tak)...
timeout /t 40 /nobreak >nul

start "" "%~dp0..\dashboard.html"

echo.
echo Done! Dashboard khud har 20 second mein naya data dikhata rahega.
echo.
pause
