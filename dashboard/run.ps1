# Labinator Dashboard Launcher
$ErrorActionPreference = "Stop"

$root = Split-Path $PSScriptRoot -Parent
$venv = Join-Path $root ".venv"
$pip  = Join-Path $venv "Scripts\pip.exe"
$py   = Join-Path $venv "Scripts\python.exe"
$req  = Join-Path $PSScriptRoot "requirements.txt"

if (-not (Test-Path $py)) {
    Write-Host "[!] Python venv not found at $venv" -ForegroundColor Red
    Write-Host "    Run: python -m venv .venv" -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Installing dashboard dependencies..." -ForegroundColor Cyan
& $pip install -q -r $req
if ($LASTEXITCODE -ne 0) { Write-Host "[!] pip install failed" -ForegroundColor Red; exit 1 }

Write-Host "[*] Starting Labinator Dashboard on port 8888..." -ForegroundColor Green
& $py -m dashboard
