# ==============================================================================
# AEGIS AI Security - Launch Desktop Application
# Ensures background engine is active and launches the native GUI window.
# ==============================================================================

[CmdletBinding()]
param()

$RootDir = Split-Path -Parent $PSScriptRoot

# 1. Ensure security engine is running
$engineProc = Get-Process -Name "aegis-service" -ErrorAction SilentlyContinue
if (-not $engineProc) {
    Write-Host "[*] AEGIS Guvenlik Motoru baslatiliyor..." -ForegroundColor Yellow
    $serviceExe = Join-Path $RootDir "target\release\aegis-service.exe"
    if (-not (Test-Path $serviceExe)) {
        $serviceExe = Join-Path $RootDir "release\aegis-service.exe"
    }
    Start-Process -FilePath $serviceExe -ArgumentList "--run-user" -WindowStyle Hidden
    Start-Sleep -Seconds 1
}

# 2. Prefer Electron Desktop Executable
$electronExe = Join-Path $RootDir "release\electron\win-unpacked\AEGIS AI Security.exe"
$tauriExe = Join-Path $RootDir "target\debug\aegis-desktop.exe"

[Environment]::SetEnvironmentVariable("ELECTRON_RUN_AS_NODE", $null, "Process")
Remove-Item env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue

if (Test-Path $electronExe) {
    Write-Host "[+] AEGIS AI Security EXE baslatiliyor: $electronExe" -ForegroundColor Green
    Start-Process -FilePath $electronExe
} elseif (Test-Path $tauriExe) {
    Write-Host "[+] AEGIS AI Security (Tauri) baslatiliyor: $tauriExe" -ForegroundColor Green
    Start-Process -FilePath $tauriExe
} else {
    Write-Host "[-] Uygulama EXE dosyasi bulunamadi. Derlemek icin: npm run electron:build" -ForegroundColor Red
}
