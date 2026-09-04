@echo off
setlocal
title ReconTitan Server
REM Resolve relative to this file, not a developer's machine-specific path.
set "VPY=%~dp0..\.venv\Scripts\python.exe"
if not exist "%VPY%" (
    echo Run setup.bat in the repository root first to create .venv.
    exit /b 1
)
"%VPY%" -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 (
    echo Existing .venv needs Python 3.11+. Rename it and rerun setup.bat.
    exit /b 1
)
cd /d "%~dp0" || exit /b 1
set "ASYNC_SCANS_ENABLED=false"
echo Starting at http://127.0.0.1:8000. Press Ctrl+C to stop.
echo If the port is occupied, this launcher fails without killing anything.
"%VPY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-server-header
exit /b %errorlevel%
