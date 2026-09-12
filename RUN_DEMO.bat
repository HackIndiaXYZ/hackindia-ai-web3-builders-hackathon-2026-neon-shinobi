@echo off
setlocal
cd /d "%~dp0"

echo ================================================
echo   AEGIS ZERO-TRUST - DEMO MODE
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

if not exist "output" mkdir "output"

echo [1/3] Generating a fresh simulated network snapshot...
pushd "Scan input"
python network_simulator.py
if errorlevel 1 (
  echo ERROR: Network simulation failed.
  popd
  pause
  exit /b 1
)
popd

echo [2/3] Starting Zero-Trust backend on port 5000...
start "Aegis Zero-Trust Backend" cmd /k "cd /d "%~dp0Scan input" && python backend_server.py --mode simulated --port 5000"

echo [3/3] Starting dashboard on port 8000...
start "Aegis Dashboard" cmd /k "cd /d "%~dp0" && python -m http.server 8000"

timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:8000/dashboard.html"

echo.
echo Dashboard: http://127.0.0.1:8000/dashboard.html
echo Backend:   http://127.0.0.1:5000/api/status
echo.
echo Keep both server windows open while using the dashboard.
endlocal
