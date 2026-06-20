$ErrorActionPreference = "Stop"

Write-Host "Starting all 5 port forwards in the background..." -ForegroundColor Cyan

# Define the port forward commands
$forwards = @(
    "kubectl port-forward svc/frontend 5174:5173 -n hpe",
    "kubectl port-forward svc/login-portal 8082:80 -n hpe",
    "kubectl port-forward svc/postgres 5432:5432 -n hpe",
    "kubectl port-forward svc/kibana 5601:5601 -n hpe",
    "kubectl port-forward svc/adminer 9090:8080 -n hpe"
)

# Start each one as a background job
$jobs = @()
foreach ($cmd in $forwards) {
    $jobs += Start-Job -ScriptBlock { Invoke-Expression $using:cmd }
}

Write-Host "✅ All port forwards started!" -ForegroundColor Green
Write-Host "They will keep running in the background of this PowerShell session." -ForegroundColor Yellow
Write-Host ""
Write-Host "=== Active Webpages ===" -ForegroundColor Cyan
Write-Host "Admin Portal:        http://localhost:5174"
Write-Host "Public Login Portal: http://localhost:8082"
Write-Host "Kibana Dashboard:    http://localhost:5601"
Write-Host "Adminer Database UI: http://localhost:9090"
Write-Host "=======================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To stop them, simply close this PowerShell window or run: " -NoNewline
Write-Host "Get-Job | Stop-Job" -ForegroundColor Magenta

# Optional: keep the script alive to show output if they want, but usually it's better to just return control to the user.
