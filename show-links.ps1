$ngrokUrl = (Invoke-RestMethod -Uri http://localhost:4040/api/tunnels -ErrorAction SilentlyContinue).tunnels[0].public_url
if (-not $ngrokUrl) { $ngrokUrl = "Waiting for Ngrok..." }

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   🚀 HPE CLUSTER IS RUNNING " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "🌐 The Applications" -ForegroundColor Yellow
Write-Host "   3D Security Dashboard: http://localhost:5173"
Write-Host "   Public Login (Local):  http://localhost:8080"
Write-Host "   Public Login (Ngrok):  $ngrokUrl" -ForegroundColor Magenta
Write-Host ""
Write-Host "🛠️ Infrastructure & Admin" -ForegroundColor Yellow
Write-Host "   Kibana (Logs):         http://localhost:5601"
Write-Host "   Adminer (Database):    http://localhost:9090"
Write-Host "   API Docs (Swagger):    http://localhost:8000/docs"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
