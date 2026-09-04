@echo off
setlocal EnableDelayedExpansion
title ReconTitan Setup

REM ============================================================================
REM  ReconTitan setup for Windows.
REM
REM  Everything this script does is printed before it does it, and the whole
REM  plan is shown up front so nothing happens that you did not agree to. It
REM  touches exactly three things: a Python virtual environment inside this
REM  folder, the packages inside that environment, and a .env file. Nothing is
REM  installed system-wide without asking first, and nothing outside this
REM  folder is modified.
REM
REM  Undo it all with uninstall.bat.
REM ============================================================================

set "ROOT=%~dp0"
cd /d "%ROOT%"
set "VENV=%ROOT%.venv"
set "MANIFEST=%ROOT%.recontitan-install.log"

echo.
echo  ============================================================================
echo.
echo     ____                      _______ __
echo    / __ \___  _________  ____/_  __(_) /_____ _____
echo   / /_/ / _ \/ ___/ __ \/ __ \/ / / / __/ __ `/ __ \
echo  / _, _/  __/ /__/ /_/ / / / / / / / /_/ /_/ / / / /
echo /_/ ^|_^|\___/\___/\____/_/ /_/_/ /_/\__/\__,_/_/ /_/
echo.
echo   External attack surface assessment
echo.
echo  ============================================================================
echo.
echo   WHAT THIS SCRIPT WILL DO
echo.
echo     1. Check that Python 3.11 or newer is installed.
echo        If it is missing, it will ASK before installing anything.
echo.
echo     2. Create a private Python environment in this folder:
echo          %VENV%
echo        This is a folder, not a system change. Deleting it undoes it.
echo.
echo     3. Install this project's Python packages INTO that folder only.
echo        Your system Python is not touched.
echo.
echo     4. Create a .env configuration file if you do not have one.
echo.
echo     5. Offer to install nmap, so port scanning stays on this machine.
echo.
echo     6. Start the scanner at http://127.0.0.1:8000
echo.
echo   WHAT IT WILL NOT DO
echo.
echo     - It will not modify anything outside this folder without asking.
echo     - It will not send your data anywhere.
echo     - It will not run any scan by itself.
echo.
echo   Everything it creates is written to:
echo     %MANIFEST%
echo   so uninstall.bat can remove exactly what was added and nothing else.
echo.
echo  ============================================================================
echo.
set "AGREE="
set /p "AGREE=  Continue? [y/N] "
if /i not "%AGREE%"=="y" (
  echo.
  echo   Cancelled. Nothing was changed.
  echo.
  pause
  exit /b 0
)

REM Preserve ownership of previous installs when setup is restarted.
echo.>> "%MANIFEST%"
if errorlevel 1 (
  echo Cannot write the install record. Check folder permissions.
  pause
  exit /b 1
)
echo # ReconTitan install manifest - what setup.bat created, for uninstall.bat>> "%MANIFEST%"
echo # Created: %DATE% %TIME%>> "%MANIFEST%"

REM ---------------------------------------------------------------------------
echo.
echo  [1/6] Checking for Python
echo  ---------------------------------------------------------------------------

set "PY_CMD="
for %%P in (py python python3) do (
  if not defined PY_CMD (
    %%P -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
    if !errorlevel! equ 0 set "PY_CMD=%%P"
  )
)

if defined PY_CMD (
  for /f "delims=" %%V in ('%PY_CMD% --version 2^>^&1') do echo        Found: %%V  ^(command: %PY_CMD%^)
) else (
  echo        Python 3.11+ was not found on this system.
  echo.
  echo        ReconTitan cannot run without it. This script can install it for
  echo        you using winget, Microsoft's official package manager, which is
  echo        built into Windows 10 and 11.
  echo.
  echo        The exact command that will run is:
  echo          winget install --id Python.Python.3.12 -e --source winget
  echo.
  set "INSTALLPY="
  set /p "INSTALLPY=       Install Python now? [y/N] "
  if /i not "!INSTALLPY!"=="y" (
    echo.
    echo        Cannot continue without Python.
    echo        Install it yourself from https://www.python.org/downloads/
    echo        and make sure to tick "Add Python to PATH", then run this again.
    echo.
    pause
    exit /b 1
  )
  where winget >nul 2>&1
  if errorlevel 1 (
    echo.
    echo        winget is not available on this system.
    echo        Please install Python manually from:
    echo          https://www.python.org/downloads/
    echo        Tick "Add Python to PATH" during installation, then run this again.
    echo.
    pause
    exit /b 1
  )
  echo        Installing Python. Windows may show a permission prompt.
  winget install --id Python.Python.3.12 -e --source winget
  if errorlevel 1 (
    echo        Python installation failed. No successful install was recorded.
    pause
    exit /b 1
  )
  echo PYTHON_INSTALLED_BY_SETUP=1>> "%MANIFEST%"
  echo.
  echo        Python installed. You must CLOSE this window and run setup.bat
  echo        again so Windows picks up the new PATH.
  echo.
  pause
  exit /b 0
)

REM ---------------------------------------------------------------------------
echo.
echo  [2/6] Creating the private Python environment
echo  ---------------------------------------------------------------------------

if exist "%VENV%\Scripts\python.exe" (
  "%VENV%\Scripts\python.exe" -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"
  if errorlevel 1 (
    echo        Existing .venv needs Python 3.11+. Rename it and run setup again.
    pause
    exit /b 1
  )
  echo        Already exists, reusing it: .venv\
) else (
  if exist "%VENV%" (
    echo        Existing .venv is incomplete or belongs to another OS.
    echo        Rename it before rerunning. It was not overwritten.
    pause
    exit /b 1
  )
  echo        Creating: .venv\
  echo        A virtual environment keeps this project's packages separate from
  echo        your system Python, so nothing here can break your other projects.
  %PY_CMD% -m venv "%VENV%"
  if errorlevel 1 (
    echo.
    echo        Failed to create the environment.
    echo        If you are using Anaconda, run "conda deactivate" first, then retry.
    echo.
    pause
    exit /b 1
  )
  echo CREATED_VENV=%VENV%>> "%MANIFEST%"
  echo        Done.
)

set "VPY=%VENV%\Scripts\python.exe"

REM ---------------------------------------------------------------------------
echo.
echo  [3/6] Installing Python packages into .venv
echo  ---------------------------------------------------------------------------
echo        These go inside .venv only. Your system Python is untouched.
echo        Reading the list from: backend\requirements.txt
echo.

"%VPY%" -m pip install --upgrade pip --quiet
if errorlevel 1 (
  echo        Could not upgrade pip. Check your connection and retry.
  pause
  exit /b 1
)
"%VPY%" -m pip install -r "%ROOT%backend\requirements.txt"
if errorlevel 1 (
  echo.
  echo        Package installation failed. The most common causes:
  echo          - No internet connection.
  echo          - A corporate proxy blocking pypi.org.
  echo          - An Anaconda environment interfering. Run "conda deactivate".
  echo.
  pause
  exit /b 1
)
echo INSTALLED_PACKAGES=1>> "%MANIFEST%"
echo.
echo        Packages installed.

REM ---------------------------------------------------------------------------
echo.
echo  [4/6] Port scanner ^(nmap^)
echo  ---------------------------------------------------------------------------

where nmap >nul 2>&1
if errorlevel 1 (
  echo        nmap is not installed.
  echo.
  echo        Without it, port scanning is skipped by default. A third-party
  echo        fallback requires ALLOW_HACKERTARGET=true and discloses the target.
  echo.
  echo        The exact command that will run is:
  echo          winget install --id Insecure.Nmap -e --source winget
  echo.
  echo        This is a system-wide install and Windows will ask permission.
  echo        Declining is fine - everything else still works.
  echo.
  set "DONMAP="
  set /p "DONMAP=       Install nmap? [y/N] "
  if /i "!DONMAP!"=="y" (
    where winget >nul 2>&1
    if errorlevel 1 (
      echo        winget is unavailable. Install nmap from https://nmap.org/download.html
    ) else (
      winget install --id Insecure.Nmap -e --source winget
      if errorlevel 1 (
        echo        nmap installation failed. Continuing without local port scanning.
      ) else (
        echo INSTALLED_NMAP=1>> "%MANIFEST%"
        echo        Installed. It may need a new terminal before it is on PATH.
      )
    )
  ) else (
    echo        Skipped. Local port scanning will be unavailable.
  )
) else (
  for /f "delims=" %%V in ('nmap --version 2^>^&1 ^| findstr /R "^Nmap"') do echo        Found: %%V
)

REM ---------------------------------------------------------------------------
echo.
echo  [5/6] Configuration
echo  ---------------------------------------------------------------------------

if exist "%ROOT%.env" (
  echo        .env already exists, leaving it exactly as it is.
) else (
  echo        Creating .env from .env.example
  echo        This holds your local settings. It is never committed to git.
  copy /y "%ROOT%.env.example" "%ROOT%.env" >nul
  if errorlevel 1 (
    echo        Could not create .env. Check folder permissions.
    pause
    exit /b 1
  )
  echo CREATED_ENV=%ROOT%.env>> "%MANIFEST%"
  echo        Done. The defaults work for local use.
)

REM ---------------------------------------------------------------------------
echo.
echo  [6/6] Starting ReconTitan
echo  ---------------------------------------------------------------------------
echo.
echo        The scanner will start at:
echo.
echo            http://127.0.0.1:8000
echo.
echo        Open that address in your browser.
echo        Press Ctrl+C in this window to stop it.
echo.
echo        Reminder: only scan domains you own or have written permission
echo        to test. Danger Mode sends real attack traffic.
echo.
echo        This launcher uses synchronous scans; Redis and Celery are not needed.
echo        MongoDB is optional for persistence. Missing optional scanner binaries
echo        reduce coverage and are reported by the application.
echo.
echo  ============================================================================
echo.

REM Uvicorn's own failure here is a raw winsock error that says nothing about
REM what to do, so the port is checked first and explained in plain terms.
set "PORT=8000"
"%VPY%" -c "import socket,sys; s=socket.socket(); r=s.connect_ex(('127.0.0.1',8000)); s.close(); sys.exit(0 if r else 1)" >nul 2>&1
if errorlevel 1 (
  echo        Port 8000 is already in use.
  echo.
  echo        Something is already listening there - most likely a copy of
  echo        ReconTitan you started earlier and left running. Check any other
  echo        terminal windows, or find it with:
  echo.
  echo            netstat -ano ^| findstr :8000
  echo.
  set "ALT="
  set /p "ALT=       Start on port 8080 instead? [y/N] "
  if /i "!ALT!"=="y" (
    set "PORT=8080"
    echo.
    echo        Using http://127.0.0.1:8080 instead.
    echo.
  ) else (
    echo.
    echo        Stop the other copy, then run setup.bat again.
    echo.
    pause
    exit /b 1
  )
)

cd /d "%ROOT%backend"
set "ASYNC_SCANS_ENABLED=false"
"%VPY%" -m uvicorn app.main:app --host 127.0.0.1 --port !PORT!
set "SERVER_EXIT=!errorlevel!"

echo.
echo   ReconTitan has stopped.
echo   Run setup.bat again to restart it, or uninstall.bat to remove everything.
echo.
pause
exit /b %SERVER_EXIT%
