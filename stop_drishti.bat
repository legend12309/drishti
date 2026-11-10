@echo off
title Stop DRISHTI Platform
echo Stopping all active DRISHTI processes...
powershell -Command "Get-Process -Name python, uvicorn -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*backend.main:app*' } | Stop-Process -Force"
taskkill /f /fi "WINDOWTITLE eq DRISHTI-DAEMON*" >nul 2>&1
echo [OK] DRISHTI processes stopped.
timeout /t 2 /nobreak >nul
