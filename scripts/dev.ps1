# ==============================================================================
# AEGIS AI Security - Development Runner Script
# Starts Vite frontend and optionally the user-mode security engine.
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$WithEngine,
    [switch]$TauriDev,
    [int]$Port = 1420
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Ensure cargo is in PATH
if (Test-Path "$env:USERPROFILE\.cargo\bin") {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         AEGIS AI Security - Development Server             " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$EngineProcess = $null

if ($WithEngine) {
    Write-Host "`n[1/2] Building and launching User-Mode Engine..." -ForegroundColor Yellow
    Push-Location $RootDir
    try {
        & cargo build -p aegis-service
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to compile aegis-service!"
            exit 1
        }
        $binPath = Join-Path $RootDir "target\debug\aegis-service.exe"
        if (Test-Path $binPath) {
            Write-Host "Starting User Engine: $binPath --run-user" -ForegroundColor Green
            $EngineProcess = Start-Process -FilePath $binPath -ArgumentList "--run-user" -PassThru -NoNewWindow
            Write-Host "Engine started with PID: $($EngineProcess.Id)" -ForegroundColor Cyan
        }
    } finally {
        Pop-Location
    }
}

$desktopDir = Join-Path $RootDir "apps\desktop"
Push-Location $desktopDir
try {
    if ($TauriDev) {
        Write-Host "`n[2/2] Launching Tauri Desktop Dev Environment..." -ForegroundColor Yellow
        & npm run tauri dev
    } else {
        Write-Host "`n[2/2] Launching Vite Frontend Dev Server on port $Port..." -ForegroundColor Yellow
        Write-Host "Open http://localhost:$Port in your browser to inspect UI." -ForegroundColor Cyan
        & npx vite --port $Port
    }
} finally {
    Pop-Location
    if ($EngineProcess -and (-not $EngineProcess.HasExited)) {
        Write-Host "`nStopping User-Mode Engine process (PID $($EngineProcess.Id))..." -ForegroundColor Yellow
        Stop-Process -Id $EngineProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Development session ended." -ForegroundColor Gray
}

