@echo off
title NetworkGuard AI - Full Stack Launcher
echo =========================================================================
echo       NetworkGuard AI: Network Anomaly Detection System (ML)
echo =========================================================================
echo.
echo Launching Backend Server on http://localhost:5000 ...
start "NetworkGuard Backend" cmd /k "%~dp0run_backend.bat"

echo Waiting 3 seconds for backend initialization...
timeout /t 3 /nobreak >nul

echo Launching Frontend Dashboard on http://localhost:5173 ...
start "NetworkGuard Frontend" cmd /k "%~dp0run_frontend.bat"

echo.
echo -------------------------------------------------------------------------
echo Both servers have been launched!
echo Access the web application at: http://localhost:5173
echo Administrator credentials:
echo   Username: admin
echo   Password: admin123
echo -------------------------------------------------------------------------
pause
