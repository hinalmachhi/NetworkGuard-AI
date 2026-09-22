@echo off
title NetworkGuard AI - Backend Server (Port 5000)
cd /d "%~dp0\backend"
echo ========================================================
echo Starting NetworkGuard AI Flask Backend on port 5000...
echo ========================================================
python app.py
pause
