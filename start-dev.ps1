param (
    [switch]$BackendOnly,
    [switch]$FrontendOnly
)

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   NEXSOLVE CYBER ATTACK FORECAST PLATFORM        " -ForegroundColor Cyan
Write-Host "   Local Development Stack (SIH Problem #26153)   " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    $VenvPython = "python"
    Write-Host "[!] Virtualenv python not found at .venv. Using system python." -ForegroundColor Yellow
} else {
    Write-Host "[+] Using virtualenv python: $VenvPython" -ForegroundColor Green
}

if ($BackendOnly) {
    Write-Host "[+] Launching FastAPI backend on http://127.0.0.1:8001 ..." -ForegroundColor Green
    & $VenvPython -m uvicorn model_service.app:app --host 127.0.0.1 --port 8001 --reload
    exit $LASTEXITCODE
}

if ($FrontendOnly) {
    Write-Host "[+] Launching Vite frontend on http://127.0.0.1:5173 ..." -ForegroundColor Green
    Set-Location (Join-Path $ScriptDir "frontend")
    npm run dev
    exit $LASTEXITCODE
}

# Launch backend in a separate process window and frontend in foreground
Write-Host "[+] Starting FastAPI backend in background (http://127.0.0.1:8001) ..." -ForegroundColor Cyan
$BackendProcess = Start-Process -FilePath $VenvPython -ArgumentList "-m uvicorn model_service.app:app --host 127.0.0.1 --port 8001 --reload" -WorkingDirectory $ScriptDir -PassThru

Start-Sleep -Seconds 2
Write-Host "[+] Backend PID: $($BackendProcess.Id)" -ForegroundColor DarkGray
Write-Host "[+] Launching React/Vite console (http://127.0.0.1:5173) ..." -ForegroundColor Cyan

try {
    Set-Location (Join-Path $ScriptDir "frontend")
    npm run dev
} finally {
    Write-Host "[*] Shutting down backend process (PID: $($BackendProcess.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $BackendProcess.Id -Force -ErrorAction SilentlyContinue
}
