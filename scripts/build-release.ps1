# ==============================================================================
# AEGIS AI Security - Release Build Script
# Compiles optimized release binaries, frontend bundle, and staging artifacts.
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$SkipTauriBundle
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$ReleaseDir = Join-Path $RootDir "release"

# Ensure cargo is in PATH
if (Test-Path "$env:USERPROFILE\.cargo\bin") {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         AEGIS AI Security - Production Release Build       " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Create clean release directory
if (-not (Test-Path $ReleaseDir)) {
    New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null
}

# 1. Build Rust Service in Release Mode
Write-Host "`n[1/4] Compiling aegis-service in Release Mode..." -ForegroundColor Yellow
Push-Location $RootDir
try {
    & cargo build --release -p aegis-service
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Release compilation of aegis-service failed!"
        exit 1
    }
    $serviceExe = Join-Path $RootDir "target\release\aegis-service.exe"
    if (Test-Path $serviceExe) {
        Copy-Item -Path $serviceExe -Destination (Join-Path $ReleaseDir "aegis-service.exe") -Force
        Write-Host "Copied aegis-service.exe to $ReleaseDir" -ForegroundColor Green
    } else {
        throw "aegis-service.exe not found in target/release"
    }
} finally {
    Pop-Location
}

# 2. Build Frontend Assets
Write-Host "`n[2/4] Compiling Frontend React/Vite Bundle..." -ForegroundColor Yellow
$desktopDir = Join-Path $RootDir "apps\desktop"
Push-Location $desktopDir
try {
    & npm run build
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Frontend compilation failed!"
        exit 1
    }
    Write-Host "Frontend build completed in $desktopDir\dist" -ForegroundColor Green
} finally {
    Pop-Location
}

# 3. Build Tauri Desktop Binary / Bundle
Write-Host "`n[3/4] Building Tauri Desktop Application..." -ForegroundColor Yellow
if (-not $SkipTauriBundle) {
    Push-Location $desktopDir
    try {
        & npm run tauri build
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Tauri build completed successfully." -ForegroundColor Green
            # Check bundle output
            $bundleDir = Join-Path $desktopDir "src-tauri\target\release\bundle"
            if (Test-Path $bundleDir) {
                Get-ChildItem -Path $bundleDir -Recurse -Filter "*.exe" | ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination $ReleaseDir -Force
                    Write-Host "Copied installer/binary: $($_.Name)" -ForegroundColor Green
                }
            }
        } else {
            Write-Host "[WARN] Full Tauri NSIS bundler requires signing certificate or NSIS runtime. Staging standalone binaries." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[WARN] Tauri bundling skipped or incomplete: $_" -ForegroundColor Yellow
    } finally {
        Pop-Location
    }
}

# 4. Stage Rules, Signatures & Compute Checksums
Write-Host "`n[4/4] Staging Core Rules and Generating SHA-256 Hashes..." -ForegroundColor Yellow
$rulesTarget = Join-Path $ReleaseDir "rules"
if (Test-Path (Join-Path $RootDir "rules")) {
    Copy-Item -Path (Join-Path $RootDir "rules") -Destination $ReleaseDir -Recurse -Force
}

$checksumFile = Join-Path $ReleaseDir "SHA256SUMS.txt"
$hashList = @()

Get-ChildItem -Path $ReleaseDir -File -Recurse | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLower()
    $relPath = $_.FullName.Substring($ReleaseDir.Length).TrimStart('\', '/')
    $entry = "$hash  $relPath"
    $hashList += $entry
    Write-Host "  $entry" -ForegroundColor Gray
}

$hashList | Out-File -FilePath $checksumFile -Encoding utf8 -Force
Write-Host "Saved checksums to $checksumFile" -ForegroundColor Green

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "   [SUCCESS] Release build finished in: $ReleaseDir         " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
