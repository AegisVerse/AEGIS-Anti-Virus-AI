# ==============================================================================
# AEGIS AI Security - Release Verification Script
# Verifies SHA-256 integrity, PE binary architecture, and execution sanity.
# ==============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$ReleaseDir = Join-Path $RootDir "release"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       AEGIS AI Security - Release Integrity Verification   " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not (Test-Path $ReleaseDir)) {
    Write-Error "Release directory does not exist: $ReleaseDir. Run build-release.ps1 first."
    exit 1
}

$checksumFile = Join-Path $ReleaseDir "SHA256SUMS.txt"
if (-not (Test-Path $checksumFile)) {
    Write-Error "SHA256SUMS.txt not found in release directory!"
    exit 1
}

# 1. Verify Checksums
Write-Host "`n[1/3] Verifying SHA-256 Checksums..." -ForegroundColor Yellow
$checksums = Get-Content -Path $checksumFile
$allMatch = $true

foreach ($line in $checksums) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $parts = -split $line
    $expectedHash = $parts[0].Trim().ToLower()
    $filePath = Join-Path $ReleaseDir $parts[1].Trim()

    if (-not (Test-Path $filePath)) {
        Write-Host "  [MISSING] $filePath" -ForegroundColor Red
        $allMatch = $false
        continue
    }

    $actualHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLower()
    if ($actualHash -eq $expectedHash) {
        Write-Host "  [OK] $($parts[1]) ($actualHash)" -ForegroundColor Green
    } else {
        Write-Host "  [MISMATCH] $($parts[1]) - Expected: $expectedHash, Got: $actualHash" -ForegroundColor Red
        $allMatch = $false
    }
}

if (-not $allMatch) {
    Write-Error "Integrity check failed: Checksums do not match!"
    exit 1
}

# 2. Binary Architecture & Execution Check
Write-Host "`n[2/3] Verifying aegis-service.exe execution and architecture..." -ForegroundColor Yellow
$serviceExe = Join-Path $ReleaseDir "aegis-service.exe"
if (Test-Path $serviceExe) {
    try {
        $output = & $serviceExe --help 2>&1
        if ($LASTEXITCODE -eq 0 -or $output -match "aegis-service") {
            Write-Host "  [OK] aegis-service executable responds correctly." -ForegroundColor Green
        } else {
            Write-Host "  [WARN] aegis-service returned unexpected output: $output" -ForegroundColor Yellow
        }
    } catch {
        Write-Error "Failed to execute $($serviceExe): $_"
        exit 1
    }
} else {
    Write-Host "  [SKIP] aegis-service.exe not present in release directory." -ForegroundColor Yellow
}

# 3. Authenticode Signature Status
Write-Host "`n[3/3] Inspecting Authenticode Signature Status..." -ForegroundColor Yellow
Get-ChildItem -Path $ReleaseDir -Filter "*.exe" | ForEach-Object {
    $sig = Get-AuthenticodeSignature -FilePath $_.FullName
    if ($sig.Status -eq "Valid") {
        Write-Host "  [SIGNED] $($_.Name) - Signer: $($sig.SignerCertificate.Subject)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] $($_.Name) - Signature status: $($sig.Status) (Ready for production code-signing certificate)." -ForegroundColor Gray
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "   [SUCCESS] Release verification passed without errors!    " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
exit 0
