@echo off
setlocal
cd /d "%~dp0"

echo ================================================
echo   AEGIS ZERO-TRUST - LIVE MODE
echo ================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python was not found in PATH.
  pause
  exit /b 1
)

if not exist "Scan input\backend_server.py" (
  echo ERROR: Scan input\backend_server.py not found.
  pause
  exit /b 1
)

start "Aegis Zero-Trust Backend LIVE" cmd /k "cd /d "%~dp0Scan input" && python backend_server.py --mode live --port 5000"
start "Aegis Dashboard" cmd /k "cd /d "%~dp0" && python -m http.server 8000"
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:8000/dashboard.html"

echo Dashboard: http://127.0.0.1:8000/dashboard.html
echo Backend:   http://127.0.0.1:5000/api/status
endlocal
