@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo     HPE Cyber Command Center - Local Demo Launcher
echo =======================================================

:: 1. Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

:: 2. Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo Please install Node.js v18+ and try again.
    pause
    exit /b 1
)

:: 3. Check/Generate ML Models
if not exist "model_output\pipeline_artifacts_v2.joblib" (
    echo [INFO] ML models not found. Generating models now...
    python export_v2_model.py
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to generate ML models.
        pause
        exit /b 1
    )
) else (
    echo [INFO] ML models found.
)

:: 4. Setup Backend
echo [INFO] Setting up Python backend...
cd backend
if not exist "venv" (
    echo [INFO] Creating Python virtual environment...
    python -m venv venv
)
echo [INFO] Installing backend dependencies...
call venv\Scripts\activate
pip install -r requirements.txt >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install backend dependencies.
    pause
    exit /b 1
)

:: 5. Start Backend
echo [INFO] Starting FastAPI Backend on port 8000...
start "HPE Backend" cmd /c "call venv\Scripts\activate && uvicorn app.main:app --reload --port 8000"
cd ..

:: 6. Setup Frontend
echo [INFO] Setting up Node frontend...
cd frontend
if not exist "node_modules" (
    echo [INFO] Installing frontend dependencies...
    call npm install >nul 2>&1
)

:: 7. Start Frontend
echo [INFO] Starting Vite Frontend on port 5173...
start "HPE Frontend" cmd /c "npm run dev"
cd ..

:: 8. Wait and open browser
echo [INFO] Waiting for services to start...
timeout /t 5 /nobreak >nul
start http://localhost:5173

echo =======================================================
echo    HPE Local Demo is now running!
echo    - Backend Console and Frontend Console have opened in new windows.
echo    - Keep those windows open to keep the application running.
echo =======================================================
pause
