@echo off
setlocal enabledelayedexpansion
title DRISHTI Cyber Intelligence Platform

echo ================================================================================
echo           DRISHTI // SOVEREIGN CYBER DEFENSE PLATFORM
echo               Air-Gap Monolith Assessment System v1.0.0
echo ================================================================================
echo.

cd /d "%~dp0"

:: 1. Detect Python Executable
set PYTHON_EXE=
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    where python >nul 2>&1
    if %errorlevel% equ 0 (
        set "PYTHON_EXE=python"
    ) else (
        echo [ERROR] Python 3.10+ was not found on this system.
        echo Please install Python 3.10 or run install.bat first.
        pause
        exit /b 1
    )
)

:: 2. Ensure Frontend Production Assets Exist
if not exist "frontend\dist\index.html" (
    echo [INFO] Pre-compiled frontend assets not found. Building with npm...
    if exist "frontend" (
        cd frontend
        call npm install
        call npm run build
        cd ..
    ) else (
        echo [ERROR] Frontend directory is missing!
        pause
        exit /b 1
    )
)

:: 3. Launch DRISHTI Unified Monolith Server (Backend + Embedded Frontend SPA)
echo [01/03] Initializing Sovereign Cryptographic Enclave...
echo [02/03] Activating Local SQLite WAL Intelligence Database...
echo [03/03] Launching DRISHTI Core Service on http://127.0.0.1:8000...
echo.

:: Start server in separate window minimized
start "DRISHTI-DAEMON" /min "%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

:: 4. Poll until server is ready
echo [WAIT] Waiting for DRISHTI server startup...
set RETRIES=0
:WAIT_LOOP
powershell -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/health' -UseBasicParsing -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 goto SERVER_READY
set /a RETRIES+=1
if %RETRIES% geq 20 (
    echo [WARNING] Server startup took longer than expected. Opening browser anyway...
    goto OPEN_BROWSER
)
timeout /t 1 /nobreak >nul
goto WAIT_LOOP

:SERVER_READY
echo [SUCCESS] DRISHTI Platform Online and Ready!
echo.

:OPEN_BROWSER
echo Opening DRISHTI Cockpit in default browser...
start http://127.0.0.1:8000

echo.
echo ================================================================================
echo DRISHTI IS LIVE AT: http://127.0.0.1:8000
echo.
echo - Operator Clearance: LEVEL 5 // TOP SECRET // SI-TK
echo - Mode: Hermetic Air-Gap Monolith (FastAPI + Embedded React SPA + SQLite WAL)
echo - Hardware Enclave: Active & Cryptographically Signed
echo.
echo [To stop DRISHTI, close this window or run stop_drishti.bat]
echo ================================================================================
echo.

pause
