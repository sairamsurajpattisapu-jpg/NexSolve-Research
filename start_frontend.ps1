#!/usr/bin/env pwsh
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   NEXSOLVE SOC COMMAND CENTER FRONTEND STARTUP   " -ForegroundColor Cyan
Write-Host "   AI-Based Network Attack Forecasting Platform   " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

Set-Location frontend
Write-Host "[+] Launching Vite development server on http://localhost:5173 ..." -ForegroundColor Green
npm run dev

