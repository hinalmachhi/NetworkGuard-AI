# NetworkGuard AI - PowerShell Launcher
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "      NetworkGuard AI: Network Anomaly Detection System (ML)" -ForegroundColor Cyan
Write-Host "=========================================================================" -ForegroundColor Cyan

$backendPath = Join-Path $PSScriptRoot "backend"
$frontendPath = Join-Path $PSScriptRoot "frontend"

Write-Host "Starting Flask Backend Server (Port 5000)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$backendPath'; python app.py"

Start-Sleep -Seconds 3

Write-Host "Starting React Frontend Dashboard (Port 5173)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$frontendPath'; npm run dev"

Write-Host "`nBoth servers have been launched in separate windows!" -ForegroundColor Green
Write-Host "Open your browser at: http://localhost:5173" -ForegroundColor White
Write-Host "Administrator Credentials:" -ForegroundColor Yellow
Write-Host "  Username: admin" -ForegroundColor White
Write-Host "  Password: admin123" -ForegroundColor White
