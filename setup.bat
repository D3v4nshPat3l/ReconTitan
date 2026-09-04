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
set "PYTHON_INSTALLED_BY_US=0"

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
echo     5. Start the scanner at http://127.0.0.1:8000
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
set /p "AGREE=  Continue? [y/N] "
if /i not "%AGREE%"=="y" (
  echo.
  echo   Cancelled. Nothing was changed.
  echo.
  pause
  exit /b 0
)

echo.> "%MANIFEST%"
echo # ReconTitan install manifest - what setup.bat created, for uninstall.bat>> "%MANIFEST%"
echo # Created: %DATE% %TIME%>> "%MANIFEST%"

REM ---------------------------------------------------------------------------
echo.
echo  [1/5] Checking for Python
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
  echo PYTHON_INSTALLED_BY_SETUP=1>> "%MANIFEST%"
  set "PYTHON_INSTALLED_BY_US=1"
  echo.
  echo        Python installed. You must CLOSE this window and run setup.bat
  echo        again so Windows picks up the new PATH.
  echo.
  pause
  exit /b 0
)

REM ---------------------------------------------------------------------------
echo.
echo  [2/5] Creating the private Python environment
echo  ---------------------------------------------------------------------------

if exist "%VENV%\Scripts\python.exe" (
  echo        Already exists, reusing it: .venv\
) else (
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
echo  [3/5] Installing Python packages into .venv
echo  ---------------------------------------------------------------------------
echo        These go inside .venv only. Your system Python is untouched.
echo        Reading the list from: backend\requirements.txt
echo.

"%VPY%" -m pip install --upgrade pip --quiet
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
echo  [4/5] Configuration
echo  ---------------------------------------------------------------------------

if exist "%ROOT%.env" (
  echo        .env already exists, leaving it exactly as it is.
) else (
  echo        Creating .env from .env.example
  echo        This holds your local settings. It is never committed to git.
  copy /y "%ROOT%.env.example" "%ROOT%.env" >nul
  echo CREATED_ENV=%ROOT%.env>> "%MANIFEST%"
  echo        Done. The defaults work for local use.
)

REM ---------------------------------------------------------------------------
echo.
echo  [5/5] Starting ReconTitan
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
echo  ============================================================================
echo.

cd /d "%ROOT%backend"
"%VPY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000

echo.
echo   ReconTitan has stopped.
echo   Run setup.bat again to restart it, or uninstall.bat to remove everything.
echo.
pause
endlocal
