# ==============================================================================
# AEGIS AI Security - Developer Setup Script
# Initializes dependencies, builds desktop node modules, and verifies crates.
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$ForceReinstall
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         AEGIS AI Security - Development Setup              " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Working directory: $RootDir"

# Step 1: Check environment
Write-Host "`n[Step 1/4] Running Environment Verification..." -ForegroundColor Yellow
$envCheck = Join-Path $ScriptDir "check-environment.ps1"
& powershell.exe -ExecutionPolicy Bypass -File $envCheck
if ($LASTEXITCODE -ne 0) {
    Write-Error "Environment check failed. Please resolve the missing dependencies above before continuing."
    exit 1
}

# Ensure cargo bin is in path
if (Test-Path "$env:USERPROFILE\.cargo\bin") {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
}

# Step 2: Install Node modules in apps/desktop
Write-Host "`n[Step 2/4] Setting up Desktop Frontend Dependencies..." -ForegroundColor Yellow
$desktopDir = Join-Path $RootDir "apps\desktop"
if (-not (Test-Path $desktopDir)) {
    Write-Error "apps/desktop directory not found!"
    exit 1
}

Push-Location $desktopDir
try {
    $nodeModules = Join-Path $desktopDir "node_modules"
    if ($ForceReinstall -or (-not (Test-Path $nodeModules))) {
        Write-Host "Running npm install in $desktopDir..." -ForegroundColor Cyan
        & npm install
        if ($LASTEXITCODE -ne 0) {
            throw "npm install failed with exit code $LASTEXITCODE"
        }
    } else {
        Write-Host "node_modules is present. Skipping npm install (use -ForceReinstall to force)." -ForegroundColor Green
    }
} finally {
    Pop-Location
}

# Step 3: Verify Rules and Signatures
Write-Host "`n[Step 3/4] Verifying Security Rules and Signatures..." -ForegroundColor Yellow
$yaraRulesDir = Join-Path $RootDir "rules\yara"
if (Test-Path $yaraRulesDir) {
    $yarCount = (Get-ChildItem -Path $yaraRulesDir -Filter "*.yar" -Recurse).Count
    Write-Host "Found $yarCount YARA rule files in $yaraRulesDir" -ForegroundColor Green
} else {
    Write-Host "Creating $yaraRulesDir directory..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $yaraRulesDir -Force | Out-Null
}

# Step 4: Cargo workspace compilation check
Write-Host "`n[Step 4/4] Verifying Rust Workspace Compilation..." -ForegroundColor Yellow
Push-Location $RootDir
try {
    & cargo check --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "cargo check failed on the workspace with exit code $LASTEXITCODE"
    }
    Write-Host "All Rust workspace crates verified successfully." -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "   [SUCCESS] Development setup complete! Ready to code.    " -ForegroundColor Green
Write-Host "   Run .\scripts\dev.ps1 to start the development servers.  " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

