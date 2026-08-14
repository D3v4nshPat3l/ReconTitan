@echo off
title ReconTitan Server
cd /d "e:\ReconTitan\backend"

echo.
echo  ==========================================
echo    RECONTITAN — Starting Secure Server
echo  ==========================================
echo.

:: Kill anything already running on port 8000
echo  [*] Clearing port 8000...
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":8000 " ^| findstr LISTENING') do (
    echo  [*] Killing old process PID %%a
    taskkill /PID %%a /F >nul 2>&1
)
timeout /t 1 /nobreak >nul

:: Check if venv exists, use it; otherwise use system python
if exist "e:\ReconTitan\backend\venv\Scripts\python.exe" (
    set PYTHON=e:\ReconTitan\backend\venv\Scripts\python.exe
) else (
    set PYTHON=python
)

echo  [*] Using Python: %PYTHON%
echo  [*] Server starting at: http://127.0.0.1:8000
echo  [*] Press Ctrl+C to stop.
echo.

%PYTHON% -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-server-header

echo.
echo  [!] Server stopped.
pause
