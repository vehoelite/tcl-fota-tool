@echo off
setlocal enabledelayedexpansion
title tcl-fota Setup
cd /d "%~dp0"

echo.
echo   tcl-fota - Firmware Updater
echo   ===========================
echo.

rem --- Find a Python interpreter. Prefer the plain "python" command over the
rem     "py" launcher: on this project's dev machine, "py" resolved to an
rem     experimental free-threaded build (python3.14t.exe) that PySide6
rem     segfaults on, while "python" pointed at a normal build that works
rem     fine. Falling back to "py" only if "python" isn't present at all. ---
where python >nul 2>nul
if %errorlevel%==0 (
    set "PYCMD=python"
) else (
    where py >nul 2>nul
    if %errorlevel%==0 (
        set "PYCMD=py"
    ) else (
        echo   Python was not found on this computer.
        echo.
        echo   This app needs Python to run. It's free and only takes a minute:
        echo     1. Go to https://www.python.org/downloads/
        echo     2. Download and run the installer
        echo     3. IMPORTANT: check the box that says "Add python.exe to PATH"
        echo        before clicking Install
        echo     4. Once it's done installing, double-click this file again
        echo.
        pause
        exit /b 1
    )
)

rem --- Check for Node.js (needed by tcl-fota.js itself) ---
where node >nul 2>nul
if not %errorlevel%==0 (
    echo   Node.js was not found on this computer.
    echo.
    echo   This app also needs Node.js. It's free and only takes a minute:
    echo     1. Go to https://nodejs.org/
    echo     2. Download and run the LTS installer ^(use the default options^)
    echo     3. Once it's done installing, double-click this file again
    echo.
    pause
    exit /b 1
)

rem --- Make sure PySide6 is installed (only needs to happen once) ---
%PYCMD% -c "import PySide6" >nul 2>nul
if not %errorlevel%==0 (
    echo   Setting up the app for its first run - this only happens once
    echo   and may take a minute...
    echo.
    %PYCMD% -m pip install --quiet --disable-pip-version-check PySide6
    if not %errorlevel%==0 (
        echo.
        echo   Something went wrong installing a required component ^(PySide6^).
        echo   Check your internet connection and try again, or ask for help
        echo   at https://github.com/vehoelite/tcl-fota-tool/issues
        echo.
        pause
        exit /b 1
    )
)

echo   Starting...
echo.
%PYCMD% main.py
if not %errorlevel%==0 (
    echo.
    echo   The app closed with an error. If this keeps happening, please
    echo   report it at https://github.com/vehoelite/tcl-fota-tool/issues
    echo.
    pause
)
