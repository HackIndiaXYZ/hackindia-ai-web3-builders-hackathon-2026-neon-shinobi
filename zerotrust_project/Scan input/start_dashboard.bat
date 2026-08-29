@echo off
REM ============================================================
REM ONE-CLICK STARTUP
REM Ye file "Scan input" folder ke andar honi chahiye.
REM Double-click karte hi: pipeline chalega, backend start hoga,
REM aur dashboard.html automatically browser mein khul jaayega.
REM ============================================================

cd /d "%~dp0"

echo ============================================
echo   Zero-Trust Dashboard - Starting Everything
echo ============================================
echo.

echo [1/6] Generating network data...
python3 network_simulator.py

echo [2/6] Running risk engine...
python3 risk_engine.py

echo [3/6] Generating policies...
python3 policy_generator.py

echo [4/6] Running AI agent...
python3 alert_agent.py

echo [5/6] Starting backend server (new window)...
start "Zero-Trust Backend" cmd /k python3 backend_server.py

echo [6/6] Waiting for server to boot, then opening dashboard...
timeout /t 3 /nobreak >nul

start "" "%~dp0..\dashboard.html"

echo.
echo Done! Dashboard should open in your browser now.
echo (Backend window ko band mat karna - wahi data serve kar raha hai)
echo.
pause
