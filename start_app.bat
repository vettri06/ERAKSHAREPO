@echo off
setlocal
echo ===================================================
echo   IoT Security Scanner - Startup Script
echo ===================================================

echo.
echo [1/2] Checking Backend...
if not exist "backend\api.py" (
    echo ERROR: backend\api.py not found!
    pause
    exit /b 1
)

echo Starting Backend Server (New Window)...
start "IoT Security Backend" cmd /k "cd backend && python api.py"

echo.
echo [2/2] Checking Frontend...
if not exist "frontend\package.json" (
    echo ERROR: frontend\package.json not found!
    pause
    exit /b 1
)

echo Starting Frontend (New Window)...
cd frontend
echo Running npm run dev...
start "IoT Security Frontend" cmd /k "npm run dev"

echo.
echo ===================================================
echo   Application started!
echo   Backend: http://localhost:5000 (usually)
echo   Frontend: http://localhost:5173 (usually)
echo ===================================================
echo.
echo You can close this window now, or keep it open.
pause
