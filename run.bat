@echo off
title Privy - Compliance Management Platform
echo ========================================
echo     🔒 Starting Privy Platform
echo ========================================
echo.

echo [1/3] Installing dependencies...
pip install -r requirements.txt
echo.

echo [2/3] Starting Main Backend (Port 8000)...
start "Privy Backend" cmd /k py main.py
timeout /t 3 /nobreak >nul
echo.

echo [3/3] Starting Auth Server (Port 8001)...
start "Privy Auth" cmd /k py auth.py
timeout /t 3 /nobreak >nul
echo.

echo ========================================
echo     ✅ Privy is now running!
echo ========================================
echo.
echo   📡 Main API:    http://localhost:8000
echo   🔑 Auth API:    http://localhost:8001
echo   📄 Login Page:  http://localhost:8000 (or open auth.html)
echo.
echo   Press any key to open the login page...
pause >nul
start http://localhost:8000
start auth.html
echo.
echo   To stop all servers, close the terminal windows.
pause