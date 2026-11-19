@echo off
title PhishGuard FastAPI Backend
echo =======================================================
echo          PhishGuard Phishing Detection API
echo =======================================================
echo.
echo Starting FastAPI server on http://127.0.0.1:8000 ...
cd /d "%~dp0backend"
python main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Default python command not in PATH, trying py launcher...
    py -3 main.py
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo Trying user AppData Python...
        "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" main.py
    )
)
pause
