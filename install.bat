@echo off
setlocal enabledelayedexpansion
title DRISHTI Automated System Installer

echo ================================================================================
echo           DRISHTI CYBER INTELLIGENCE PLATFORM // INSTALLER
echo ================================================================================
echo.

cd /d "%~dp0"

:: 1. Check Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [FATAL ERROR] Python is not installed or not in PATH.
    echo Please download and install Python 3.10+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [01/04] Checking Python environment...
python --version

:: 2. Create or verify Virtual Environment
if not exist ".venv\Scripts\python.exe" (
    echo [02/04] Creating Python virtual environment in .venv...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
) else (
    echo [02/04] Virtual environment (.venv) already exists.
)

:: 3. Install Requirements
echo [03/04] Installing Python dependencies from requirements.txt...
.venv\Scripts\python.exe -m pip install --upgrade pip >nul 2>&1
.venv\Scripts\python.exe -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install some requirements.
    pause
    exit /b 1
)

:: 4. Verify Local Storage & Enclave
echo [04/04] Initializing local database directory and permissions...
if not exist "data" mkdir data

echo.
echo ================================================================================
echo [SUCCESS] DRISHTI PLATFORM SUCCESSFULLY INSTALLED!
echo ================================================================================
echo.
echo You can now run DRISHTI at any time by double-clicking:
echo   - "start_drishti.bat"     (Launches platform in web browser)
echo   - "start_desktop_app.bat" (Launches platform as a standalone desktop window)
echo.
echo Press any key to start DRISHTI now...
pause >nul
call start_drishti.bat
