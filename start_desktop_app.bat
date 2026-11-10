@echo off
setlocal enabledelayedexpansion
title DRISHTI Desktop Application Mode

echo ================================================================================
echo           DRISHTI // STANDALONE DESKTOP APPLICATION LAUNCHER
echo ================================================================================
echo.

cd /d "%~dp0"

:: 1. Detect Python Executable
set PYTHON_EXE=
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

:: 2. Check if server is already running
powershell -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/health' -UseBasicParsing -TimeoutSec 1; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %errorlevel% neq 0 (
    echo Starting DRISHTI background daemon...
    start "DRISHTI-DAEMON" /min "%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
    
    :WAIT_LOOP
    timeout /t 1 /nobreak >nul
    powershell -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/health' -UseBasicParsing -TimeoutSec 1; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
    if %errorlevel% neq 0 goto WAIT_LOOP
)

echo DRISHTI Enclave online. Launching native desktop window...

:: 3. Launch in standalone Native App Window Mode (Edge or Chrome)
if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --app=http://127.0.0.1:8000 --window-size=1400,900
    exit /b 0
)

if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
    start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" --app=http://127.0.0.1:8000 --window-size=1400,900
    exit /b 0
)

:: Fallback to standard browser open
start http://127.0.0.1:8000
exit /b 0
