# ==============================================================================
# AEGIS AI Security - Test Runner Script
# Executes Rust workspace tests and Frontend Vitest suite.
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$RustOnly,
    [switch]$UiOnly
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Ensure cargo is in PATH
if (Test-Path "$env:USERPROFILE\.cargo\bin") {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "             AEGIS AI Security - Test Suite                 " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$RustSuccess = $true
$UiSuccess = $true
$TypecheckSuccess = $true

# Part 1: Rust Backend Tests
if (-not $UiOnly) {
    Write-Host "`n[1/3] Running Rust Workspace Tests (Cargo)..." -ForegroundColor Yellow
    Push-Location $RootDir
    try {
        & cargo test --workspace -- --nocapture
        if ($LASTEXITCODE -ne 0) {
            $RustSuccess = $false
            Write-Host "Rust tests failed with exit code $LASTEXITCODE" -ForegroundColor Red
        } else {
            Write-Host "All Rust unit and integration tests passed." -ForegroundColor Green
        }
    } finally {
        Pop-Location
    }
}

# Part 2: Frontend TypeScript & Vitest Tests
if (-not $RustOnly) {
    $desktopDir = Join-Path $RootDir "apps\desktop"
    Push-Location $desktopDir
    try {
        Write-Host "`n[2/3] Running Frontend TypeScript Typecheck..." -ForegroundColor Yellow
        & npm run typecheck
        if ($LASTEXITCODE -ne 0) {
            $TypecheckSuccess = $false
            Write-Host "TypeScript typecheck failed!" -ForegroundColor Red
        } else {
            Write-Host "TypeScript compilation clean with zero errors." -ForegroundColor Green
        }

        Write-Host "`n[3/3] Running Frontend Vitest Test Suite..." -ForegroundColor Yellow
        & npm test
        if ($LASTEXITCODE -ne 0) {
            $UiSuccess = $false
            Write-Host "Frontend Vitest tests failed!" -ForegroundColor Red
        } else {
            Write-Host "Frontend Vitest tests passed." -ForegroundColor Green
        }
    } finally {
        Pop-Location
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "                  Test Execution Summary                    " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
if (-not $UiOnly) {
    $rColor = if ($RustSuccess) { "Green" } else { "Red" }
    $rTxt = if ($RustSuccess) { "PASSED" } else { "FAILED" }
    Write-Host "  Rust Workspace Tests:        $rTxt" -ForegroundColor $rColor
}
if (-not $RustOnly) {
    $tColor = if ($TypecheckSuccess) { "Green" } else { "Red" }
    $tTxt = if ($TypecheckSuccess) { "PASSED" } else { "FAILED" }
    Write-Host "  Frontend Typecheck (tsc):    $tTxt" -ForegroundColor $tColor

    $uColor = if ($UiSuccess) { "Green" } else { "Red" }
    $uTxt = if ($UiSuccess) { "PASSED" } else { "FAILED" }
    Write-Host "  Frontend Vitest Suite:       $uTxt" -ForegroundColor $uColor
}
Write-Host "============================================================" -ForegroundColor Cyan

if ($RustSuccess -and $UiSuccess -and $TypecheckSuccess) {
    Write-Host "ALL TEST SUITES PASSED! [SUCCESS]" -ForegroundColor Green
    exit 0
} else {
    Write-Host "TEST FAILURES DETECTED! [FAILURE]" -ForegroundColor Red
    exit 1
}

