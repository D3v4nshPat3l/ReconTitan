@echo off
setlocal EnableDelayedExpansion
title ReconTitan Uninstall

REM ============================================================================
REM  ReconTitan uninstall for Windows.
REM
REM  This asks about every item separately and defaults to KEEPING it. Nothing
REM  is removed unless you type y for that specific item, and each item's exact
REM  path and size is shown before the question.
REM
REM  It only offers to remove things setup.bat created. Your scan reports, your
REM  .env secrets and the project source are handled separately and explicitly.
REM ============================================================================

set "ROOT=%~dp0"
cd /d "%ROOT%"
set "VENV=%ROOT%.venv"
set "MANIFEST=%ROOT%.recontitan-install.log"
set "REMOVED=0"
set "KEPT=0"

echo.
echo  ============================================================================
echo.
echo    ReconTitan - Uninstall
echo.
echo  ============================================================================
echo.
echo   This will go through everything setup.bat created, ONE ITEM AT A TIME.
echo.
echo   For each item you will see:
echo     - exactly what it is
echo     - exactly where it lives
echo     - how much disk space it uses
echo.
echo   Then you choose to keep it or remove it. The default is KEEP.
echo   Nothing is deleted unless you type "y" for that specific item.
echo.
if exist "%MANIFEST%" (
  echo   Reading the install record from:
  echo     %MANIFEST%
) else (
  echo   No install record found. That is fine - this script will still check
  echo   for the standard items and ask about each one it finds.
)
echo.
echo  ============================================================================
echo.
set /p "GO=  Continue? [y/N] "
if /i not "%GO%"=="y" (
  echo.
  echo   Cancelled. Nothing was changed.
  echo.
  pause
  exit /b 0
)

REM ---------------------------------------------------------------------------
echo.
echo  ---------------------------------------------------------------------------
echo   ITEM 1 of 4:  Python environment ^(.venv^)
echo  ---------------------------------------------------------------------------

if exist "%VENV%" (
  set "VSIZE=unknown"
  for /f "tokens=3" %%S in ('dir /s /-c "%VENV%" 2^>nul ^| findstr /C:"File(s)"') do set "VSIZE=%%S"
  echo.
  echo     What:  The private Python environment and every package installed
  echo            into it ^(FastAPI, uvicorn, pymongo and the rest^).
  echo     Where: %VENV%
  echo     Size:  approximately !VSIZE! bytes
  echo.
  echo     Removing this frees the most space. It does NOT affect your system
  echo     Python or any other project. You can recreate it any time by
  echo     running setup.bat again.
  echo.
  set /p "D1=    Remove it? [y/N] "
  if /i "!D1!"=="y" (
    echo     Deleting %VENV% ...
    rmdir /s /q "%VENV%"
    if exist "%VENV%" (
      echo     Could not fully delete it. Close any program using it and retry.
    ) else (
      echo     Removed.
      set /a REMOVED+=1
    )
  ) else (
    echo     Kept.
    set /a KEPT+=1
  )
) else (
  echo.
  echo     Not present - nothing to remove.
)

REM ---------------------------------------------------------------------------
echo.
echo  ---------------------------------------------------------------------------
echo   ITEM 2 of 4:  Configuration file ^(.env^)
echo  ---------------------------------------------------------------------------

if exist "%ROOT%.env" (
  echo.
  echo     What:  Your local settings. THIS MAY CONTAIN SECRETS - your admin
  echo            token, API keys and database passwords.
  echo     Where: %ROOT%.env
  echo.
  echo     Keep it if you plan to run ReconTitan again and do not want to
  echo     reconfigure. Remove it if you are wiping this machine clean.
  echo.
  set /p "D2=    Remove it? [y/N] "
  if /i "!D2!"=="y" (
    del /q "%ROOT%.env"
    echo     Removed.
    set /a REMOVED+=1
  ) else (
    echo     Kept.
    set /a KEPT+=1
  )
) else (
  echo.
  echo     Not present - nothing to remove.
)

REM ---------------------------------------------------------------------------
echo.
echo  ---------------------------------------------------------------------------
echo   ITEM 3 of 4:  Python bytecode caches ^(__pycache__^)
echo  ---------------------------------------------------------------------------
echo.
echo     What:  Compiled bytecode Python generates automatically while running.
echo     Where: __pycache__ folders throughout this project.
echo.
echo     These are always safe to remove. Python simply regenerates them.
echo.
set /p "D3=    Remove them? [y/N] "
if /i "%D3%"=="y" (
  set "PC=0"
  for /d /r "%ROOT%" %%D in (__pycache__) do (
    if exist "%%D" (
      rmdir /s /q "%%D" 2>nul
      set /a PC+=1
    )
  )
  echo     Removed !PC! cache folder^(s^).
  set /a REMOVED+=1
) else (
  echo     Kept.
  set /a KEPT+=1
)

REM ---------------------------------------------------------------------------
echo.
echo  ---------------------------------------------------------------------------
echo   ITEM 4 of 4:  Python itself
echo  ---------------------------------------------------------------------------
echo.

findstr /C:"PYTHON_INSTALLED_BY_SETUP=1" "%MANIFEST%" >nul 2>&1
if errorlevel 1 (
  echo     Python was ALREADY on this system before you ran setup.bat.
  echo.
  echo     This script will NOT touch it. Other software on your machine
  echo     almost certainly depends on it.
) else (
  echo     setup.bat installed Python on this machine using winget.
  echo.
  echo     Be careful here. Other software may have started using it since.
  echo     If you are not certain, keep it - it is small and harmless.
  echo.
  echo     The exact command that would run is:
  echo       winget uninstall --id Python.Python.3.12 -e
  echo.
  set /p "D4=    Uninstall Python? [y/N] "
  if /i "!D4!"=="y" (
    winget uninstall --id Python.Python.3.12 -e
    echo     Done.
    set /a REMOVED+=1
  ) else (
    echo     Kept.
    set /a KEPT+=1
  )
)

REM ---------------------------------------------------------------------------
echo.
echo  ---------------------------------------------------------------------------
echo   NOT TOUCHED BY THIS SCRIPT
echo  ---------------------------------------------------------------------------
echo.
echo     - The project source code in this folder. Delete the folder yourself
echo       if you want it gone.
echo     - MongoDB, Redis, Docker or Ollama, if you installed any of them.
echo       They were not installed by setup.bat, so removing them is your call.
echo     - Any scan reports you exported to your Downloads folder.
echo.

REM Keep the record if anything survived: it is what tells a later run whether
REM setup installed Python, and deleting it would lose that.
if %KEPT% equ 0 (
  if exist "%MANIFEST%" del /q "%MANIFEST%" 2>nul
) else (
  echo   Install record kept at %MANIFEST%, since some items remain.
  echo.
)

echo  ============================================================================
echo.
echo    Finished.  %REMOVED% item^(s^) removed,  %KEPT% item^(s^) kept.
echo.
echo    To reinstall at any time, run setup.bat
echo.
echo  ============================================================================
echo.
pause
endlocal
