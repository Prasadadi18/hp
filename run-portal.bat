@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo     HPE Cyber Command Center - Portal-Only Launcher
echo =======================================================
echo.
echo   Mode: Public Login Portal via Ngrok
echo   Data flows ONLY from portal logins (no dataset replay)
echo.

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

:: 3. Stop any previously running stacks (both files) and remove orphans
echo [INFO] Stopping any existing containers from all stacks...
docker compose -f docker-compose.portal.yml down --remove-orphans 2>nul
docker compose down --remove-orphans 2>nul

:: 4. Start Portal-Only Docker Compose Stack
echo [INFO] Starting Portal-Only stack (no dataset streaming)...
docker compose -f docker-compose.portal.yml up -d --build --remove-orphans
if %errorlevel% neq 0 (
    echo [ERROR] Failed to start Docker Compose.
    pause
    exit /b 1
)

:: 5. Wait for Backend Health
echo [INFO] Waiting for the backend service to become healthy...
:WAIT_LOOP
curl -s http://localhost:8000/api/health >nul 2>&1
if %errorlevel% neq 0 (
    echo     Waiting...
    timeout /t 5 /nobreak >nul
    goto WAIT_LOOP
)
echo [INFO] Backend is healthy!

:: 6. Extract Ngrok URL (if running)
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

:: 7. Open Dashboard
echo [INFO] Opening the 3D Security Dashboard in your browser...
start http://localhost:5173

echo =======================================================
echo    HPE Cyber Command Center - Portal-Only Mode
echo =======================================================
echo.
echo    3D Dashboard:    http://localhost:5173
echo    Public Portal:   http://localhost:8080
echo    API Backend:     http://localhost:8000
echo    Adminer DB:      http://localhost:9090
echo    Kibana:          http://localhost:5601
echo    Ngrok Inspector: http://localhost:4040
echo.
echo    Dataset streaming is DISABLED.
echo    Only portal logins flow through the pipeline.
echo =======================================================
pause
