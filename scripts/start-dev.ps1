$ErrorActionPreference = 'Stop'
$ResearchRoot = Split-Path -Parent $PSScriptRoot
$ProductionRoot = 'C:\Users\saira\OneDrive\Documents\nexsolve'
$StatePath = Join-Path $PSScriptRoot 'dev-processes.json'
$LogRoot = Join-Path $PSScriptRoot 'logs'

if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python was not found on PATH.' }
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw 'npm was not found on PATH.' }
if (-not (Test-Path (Join-Path $ResearchRoot 'model_service\requirements.txt'))) { throw 'Research model-service requirements are missing.' }
if (-not (Test-Path (Join-Path $ProductionRoot 'backend\node_modules'))) { throw 'Backend dependencies are missing.' }
if (-not (Test-Path (Join-Path $ProductionRoot 'frontend\node_modules'))) { throw 'Frontend dependencies are missing.' }
python -c "import fastapi, uvicorn" | Out-Null
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
if (Test-Path $StatePath) { & (Join-Path $PSScriptRoot 'stop-dev.ps1') }

$processes = @()
$model = Start-Process python -ArgumentList '-m','uvicorn','model_service.app:app','--host','127.0.0.1','--port','8001' -WorkingDirectory $ResearchRoot -RedirectStandardOutput (Join-Path $LogRoot 'model-service.log') -RedirectStandardError (Join-Path $LogRoot 'model-service.error.log') -PassThru
$processes += [pscustomobject]@{ name = 'model-service'; pid = $model.Id }
$healthy = $false
for ($attempt = 1; $attempt -le 40; $attempt++) {
  try { $health = Invoke-RestMethod 'http://127.0.0.1:8001/health'; if ($health.model_loaded -eq $true) { $healthy = $true; break } } catch { }
  Start-Sleep -Milliseconds 250
}
if (-not $healthy) { & (Join-Path $PSScriptRoot 'stop-dev.ps1'); throw 'Model service did not become healthy. See scripts/logs.' }

$oldForecastUrl = $env:FORECAST_ENGINE_URL
$env:FORECAST_ENGINE_URL = 'http://127.0.0.1:8001'
$backend = Start-Process npm.cmd -ArgumentList 'run','dev' -WorkingDirectory (Join-Path $ProductionRoot 'backend') -RedirectStandardOutput (Join-Path $LogRoot 'backend.log') -RedirectStandardError (Join-Path $LogRoot 'backend.error.log') -PassThru
if ($null -eq $oldForecastUrl) { Remove-Item Env:FORECAST_ENGINE_URL -ErrorAction SilentlyContinue } else { $env:FORECAST_ENGINE_URL = $oldForecastUrl }
$processes += [pscustomobject]@{ name = 'backend'; pid = $backend.Id }
$frontend = Start-Process npm.cmd -ArgumentList 'run','dev','--','--host','127.0.0.1','--port','5173' -WorkingDirectory (Join-Path $ProductionRoot 'frontend') -RedirectStandardOutput (Join-Path $LogRoot 'frontend.log') -RedirectStandardError (Join-Path $LogRoot 'frontend.error.log') -PassThru
$processes += [pscustomobject]@{ name = 'frontend'; pid = $frontend.Id }
$processes | ConvertTo-Json | Set-Content -Path $StatePath -Encoding UTF8
Write-Output 'NexSolve development services started.'
Write-Output 'Model:    http://127.0.0.1:8001/health'
Write-Output 'Backend:  http://127.0.0.1:3000/api/health'
Write-Output 'Forecast: http://127.0.0.1:3000/api/forecast/health'
Write-Output 'Frontend: http://127.0.0.1:5173'
Write-Output "Logs:     $LogRoot"
