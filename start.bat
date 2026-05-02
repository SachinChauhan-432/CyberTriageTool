@echo off
echo ============================================
echo   NexusGuard Enterprise Platform v2.0
echo   Phase 12: Hardened Deployment
echo ============================================
echo.

REM Start Blockchain Logger (Port 5002)
echo [1/4] Starting Blockchain Logger...
start "NexusGuard - Blockchain Logger" cmd /c "cd services\blockchain_logger && python app.py"

REM Start Analytics Engine (Port 5001)
echo [2/4] Starting Analytics Engine (AI + Security)...
start "NexusGuard - Analytics Engine" cmd /c "cd services\analytics_engine && python app.py"

REM Wait for analytics engine to initialize DB and AI models
timeout /t 4 >nul

REM Start API Gateway (Port 5000)
echo [3/4] Starting API Gateway (Security Headers + Proxy)...
start "NexusGuard - API Gateway" cmd /c "cd services\api_gateway && python app.py"

REM Start Hardened Agent
echo [4/4] Starting Endpoint Agent (HMAC Signed)...
start "NexusGuard - Agent" cmd /c "cd services\agent && python agent.py"

echo.
echo ============================================
echo   All services started successfully!
echo ============================================
echo.
echo   Dashboard:      http://localhost:5000
echo   Health Check:   http://localhost:5000/api/health
echo.
echo   Security:
echo     - Security headers enabled
echo     - Rate limiting active (120 req/min)
echo     - Input validation enforced
echo     - HMAC payload signing enabled
echo     - Blockchain audit trail active
echo.
echo   Testing:
echo     Load Test:     python tests\load_test.py
echo     Security Test: python tests\security_test.py
echo.
pause
