#!/usr/bin/env pwsh
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   NEXSOLVE API BACKEND SERVICE STARTUP          " -ForegroundColor Cyan
Write-Host "   SIH 2026 Problem Statement ID: 26153          " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$VenvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[!] Virtual environment not found at .\.venv. Using system python." -ForegroundColor Yellow
    $VenvPython = "python"
}

Write-Host "[+] Launching FastAPI backend on http://127.0.0.1:8000 ..." -ForegroundColor Green
& $VenvPython -m uvicorn model_service.main:app --host 127.0.0.1 --port 8000 --reload

