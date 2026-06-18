@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo     HPE Cyber Command Center - Docker Compose Launcher
echo =======================================================

:: 1. Check Docker Desktop
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker Desktop is not running or not installed.
    echo Please start Docker Desktop and try again.
    pause
    exit /b 1
)

:: 2. Check/Generate ML Models
if not exist "model_output\pipeline_artifacts_v2.joblib" (
    echo [INFO] ML models not found. Generating models now...
    python export_v2_model.py
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to generate ML models. Please check Python dependencies.
        pause
        exit /b 1
    )
) else (
    echo [INFO] ML models found.
)

:: 3. Start Docker Compose Stack
echo [INFO] Starting Docker Compose stack (including live-replay)...
docker compose --profile live-replay up -d --build
if %errorlevel% neq 0 (
    echo [ERROR] Failed to start Docker Compose.
    pause
    exit /b 1
)

:: 4. Wait for Backend Health
echo [INFO] Waiting for the backend service to become healthy...
:WAIT_LOOP
curl -s http://localhost:8000/api/health >nul 2>&1
if %errorlevel% neq 0 (
    echo     Waiting...
    timeout /t 5 /nobreak >nul
    goto WAIT_LOOP
)
echo [INFO] Backend is healthy!

:: 5. Extract Ngrok URL (if running)
echo [INFO] Attempting to retrieve Ngrok public URL...
curl -s http://localhost:4040/api/tunnels > ngrok_temp.json 2>nul
if %errorlevel% equ 0 (
    findstr /C:"public_url" ngrok_temp.json > nul 2>&1
    if !errorlevel! equ 0 (
        echo [SUCCESS] Ngrok Tunnel is active!
        echo You can access the Public Login Portal from the internet.
    ) else (
        echo [INFO] Ngrok tunnel not active or not yet ready.
    )
    del ngrok_temp.json
) else (
    echo [INFO] Ngrok API not reachable yet.
)

:: 6. Open Dashboard
echo [INFO] Opening the 3D Security Dashboard in your browser...
start http://localhost:5173

echo =======================================================
echo    HPE Cyber Command Center is now running!
echo    - 3D Dashboard: http://localhost:5173
echo    - Public Portal: http://localhost:8080
echo    - Adminer DB: http://localhost:9090
echo    - API Backend: http://localhost:8000
echo =======================================================
pause
