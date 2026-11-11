# ==============================================================================
# AEGIS AI Security - Environment Diagnostic Script
# Verifies all necessary development tools, runtimes, and compiler toolchains.
# ==============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   AEGIS AI Security - Development Environment Checker     " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$AllRequiredPassed = $true
$MissingItems = @()

# Ensure user cargo bin is in path for current session
if (Test-Path "$env:USERPROFILE\.cargo\bin") {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
}

# 1. Windows OS & Architecture
$os = Get-CimInstance Win32_OperatingSystem
$arch = $env:PROCESSOR_ARCHITECTURE
Write-Host "[1/10] Windows OS Information:" -ForegroundColor Yellow
Write-Host "       OS:           $($os.Caption) (Build $($os.BuildNumber))"
Write-Host "       Architecture: $arch"
if ($arch -ne "AMD64") {
    Write-Host "       [WARN] Recommended architecture is AMD64 (x86_64)." -ForegroundColor Yellow
} else {
    Write-Host "       [OK] Valid 64-bit Windows environment." -ForegroundColor Green
}

# 2. Administrator Status
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "`n[2/10] Privilege Status:" -ForegroundColor Yellow
if ($isAdmin) {
    Write-Host "       Running with Administrator privileges (Full access)." -ForegroundColor Green
} else {
    Write-Host "       Running as standard user. (Note: Service registration and driver tests require elevation)." -ForegroundColor Cyan
}

# 3. Rust Toolchain (rustc)
Write-Host "`n[3/10] Rust Toolchain (rustc):" -ForegroundColor Yellow
try {
    $rustcVer = & rustc --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $rustcVer) {
        Write-Host "       [OK] $rustcVer" -ForegroundColor Green
    } else {
        throw "rustc command returned non-zero"
    }
} catch {
    Write-Host "       [FAIL] rustc not found or not in PATH." -ForegroundColor Red
    $AllRequiredPassed = $false
    $MissingItems += "Rust toolchain (rustup-init.exe / rustc)"
}

# 4. Cargo
Write-Host "`n[4/10] Cargo Package Manager:" -ForegroundColor Yellow
try {
    $cargoVer = & cargo --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $cargoVer) {
        Write-Host "       [OK] $cargoVer" -ForegroundColor Green
    } else {
        throw "cargo command returned non-zero"
    }
} catch {
    Write-Host "       [FAIL] cargo not found or not in PATH." -ForegroundColor Red
    $AllRequiredPassed = $false
    $MissingItems += "Cargo (part of Rust toolchain)"
}

# 5. Node.js
Write-Host "`n[5/10] Node.js Runtime:" -ForegroundColor Yellow
try {
    $nodeVer = & node --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $nodeVer) {
        Write-Host "       [OK] Node.js $nodeVer" -ForegroundColor Green
    } else {
        throw "node returned non-zero"
    }
} catch {
    Write-Host "       [FAIL] Node.js not found in PATH." -ForegroundColor Red
    $AllRequiredPassed = $false
    $MissingItems += "Node.js (v18+ recommended)"
}

# 6. npm Package Manager
Write-Host "`n[6/10] npm Package Manager:" -ForegroundColor Yellow
try {
    $npmVer = & npm --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $npmVer) {
        Write-Host "       [OK] npm $npmVer" -ForegroundColor Green
    } else {
        throw "npm returned non-zero"
    }
} catch {
    Write-Host "       [FAIL] npm not found in PATH." -ForegroundColor Red
    $AllRequiredPassed = $false
    $MissingItems += "npm (bundled with Node.js)"
}

# 7. Microsoft Visual C++ Build Tools & Linker
Write-Host "`n[7/10] MSVC Linker (link.exe):" -ForegroundColor Yellow
$linkFound = $false
try {
    $linkOut = & where.exe link 2>$null
    if ($linkOut) {
        Write-Host "       [OK] Linker located: $($linkOut[0])" -ForegroundColor Green
        $linkFound = $true
    }
} catch {}
if (-not $linkFound) {
    # Check default Visual Studio paths
    $vsPath = "C:\Program Files (x86)\Microsoft Visual Studio"
    $vs2022Path = "C:\Program Files\Microsoft Visual Studio"
    if ((Test-Path $vsPath) -or (Test-Path $vs2022Path)) {
        Write-Host "       [OK] Visual Studio / Build Tools directory detected." -ForegroundColor Green
    } else {
        Write-Host "       [WARN] MSVC link.exe not found directly in current PATH. Cargo may still invoke it via cc crate." -ForegroundColor Yellow
    }
}

# 8. Git
Write-Host "`n[8/10] Git Version Control:" -ForegroundColor Yellow
try {
    $gitVer = & git --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitVer) {
        Write-Host "       [OK] $gitVer" -ForegroundColor Green
    } else {
        throw "git error"
    }
} catch {
    Write-Host "       [WARN] Git not found in PATH." -ForegroundColor Yellow
}

# 9. WebView2 Runtime
Write-Host "`n[9/10] Microsoft WebView2 Runtime:" -ForegroundColor Yellow
$wv2Installed = $false
$wv2Reg = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-F552-4465-B6A2-9E8628258172}",
    "HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-F552-4465-B6A2-9E8628258172}",
    "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-F552-4465-B6A2-9E8628258172}"
)
foreach ($regPath in $wv2Reg) {
    if (Test-Path $regPath) {
        $wv2Ver = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).pv
        if ($wv2Ver) {
            Write-Host "       [OK] Evergreen WebView2 installed (Version $wv2Ver)" -ForegroundColor Green
            $wv2Installed = $true
            break
        }
    }
}
if (-not $wv2Installed) {
    Write-Host "       [WARN] WebView2 registry key not found directly. (Standard on Windows 10/11)." -ForegroundColor Yellow
}

# 10. Python
Write-Host "`n[10/10] Python (Optional for ML analysis & asset generation):" -ForegroundColor Yellow
try {
    $pyVer = & python --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $pyVer) {
        Write-Host "       [OK] $pyVer" -ForegroundColor Green
    } else {
        throw "python error"
    }
} catch {
    Write-Host "       [INFO] Python not found (Optional)." -ForegroundColor Gray
}

Write-Host "`n============================================================" -ForegroundColor Cyan
if ($AllRequiredPassed) {
    Write-Host "   [SUCCESS] Environment is fully configured for AEGIS AI! " -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "   [ERROR] Missing required dependencies:" -ForegroundColor Red
    foreach ($m in $MissingItems) {
        Write-Host "   - $m" -ForegroundColor Red
    }
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 1
}

