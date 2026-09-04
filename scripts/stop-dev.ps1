$ErrorActionPreference = 'Stop'
$StatePath = Join-Path $PSScriptRoot 'dev-processes.json'
if (-not (Test-Path $StatePath)) { Write-Output 'No NexSolve development process state found.'; exit 0 }
$processes = Get-Content $StatePath -Raw | ConvertFrom-Json
foreach ($entry in @($processes)) {
  $process = Get-Process -Id ([int]$entry.pid) -ErrorAction SilentlyContinue
  if ($null -ne $process) { Stop-Process -Id $process.Id -Force }
}
Remove-Item $StatePath -Force
Write-Output 'NexSolve development processes stopped.'
