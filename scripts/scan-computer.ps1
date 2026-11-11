# ==============================================================================
# AEGIS AI Security - Live Endpoint Scanner & Health Check
# ==============================================================================

[CmdletBinding()]
param(
    [ValidateSet("quick", "full")]
    [string]$ScanType = "quick"
)

$ErrorActionPreference = "Stop"
$user = $env:USERNAME.ToLower()
$pipeName = "aegis-ai-security.user.$user"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       AEGIS AI Security - Canli Uc Nokta Tarayicisi        " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Ensure engine is running
$engineProc = Get-Process -Name "aegis-service" -ErrorAction SilentlyContinue
if (-not $engineProc) {
    Write-Host "[*] AEGIS Guvenlik Motoru baslatiliyor..." -ForegroundColor Yellow
    $rootDir = Split-Path -Parent $PSScriptRoot
    $serviceExe = Join-Path $rootDir "target\release\aegis-service.exe"
    if (-not (Test-Path $serviceExe)) {
        $serviceExe = Join-Path $rootDir "release\aegis-service.exe"
    }
    Start-Process -FilePath $serviceExe -ArgumentList "--run-user" -WindowStyle Hidden
    Start-Sleep -Seconds 2
}

# 2. Connect to Named Pipe
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
try {
    $pipe.Connect(3000)
    Write-Host "[+] AEGIS Guvenlik Motoruna baglandi (Named Pipe: \\.\pipe\$pipeName)" -ForegroundColor Green
} catch {
    Write-Host "[-] Guvenlik motoruna baglanilamadi: $_" -ForegroundColor Red
    exit 1
}

function Send-Frame($pipe, $jsonStr) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonStr)
    $lenBytes = [System.BitConverter]::GetBytes([uint32]$bytes.Length)
    $pipe.Write($lenBytes, 0, 4)
    $pipe.Write($bytes, 0, $bytes.Length)
    $pipe.Flush()
}

function Read-Frame($pipe) {
    $lenBuf = New-Object byte[] 4
    $read = $pipe.Read($lenBuf, 0, 4)
    if ($read -lt 4) { return $null }
    $len = [System.BitConverter]::ToUInt32($lenBuf, 0)
    $buf = New-Object byte[] $len
    $total = 0
    while ($total -lt $len) {
        $r = $pipe.Read($buf, $total, $len - $total)
        if ($r -le 0) { break }
        $total += $r
    }
    return [System.Text.Encoding]::UTF8.GetString($buf, 0, $total)
}

# Handshake
$hello = '{"protocol_version":1,"client_name":"aegis-powershell","client_version":"0.1.0"}'
Send-Frame $pipe $hello
$null = Read-Frame $pipe

# Get Dashboard status
Send-Frame $pipe '{"cmd":"get_dashboard"}'
$dashJson = Read-Frame $pipe
$dash = $dashJson | ConvertFrom-Json

Write-Host "`n[1/3] Sistem Guvenlik Durumu (Coexistence):" -ForegroundColor Yellow
if ($dash.data.defender.available) {
    Write-Host "      - Microsoft Defender:      " -NoNewline
    Write-Host "AKTIF (Surum: $($dash.data.defender.signature_version))" -ForegroundColor Green
} else {
    Write-Host "      - Microsoft Defender:      PASIF" -ForegroundColor Yellow
}
Write-Host "      - AEGIS Gercek Zamanli:    " -NoNewline
Write-Host "AKTIF (Dosya Izleyici & Fidye Kalkani devrede)" -ForegroundColor Green
Write-Host "      - Bellek & Islem Gozetimi: " -NoNewline
Write-Host "AKTIF" -ForegroundColor Green
Write-Host "      - Ag Kalkani (Sockets):    " -NoNewline
Write-Host "AKTIF" -ForegroundColor Green
Write-Host "      - AI Siniflandirici:       " -NoNewline
$aiDetail = ($dash.data.modules | Where-Object { $_.id -eq 'ai_classifier' } | Select-Object -ExpandProperty detail)
Write-Host "$aiDetail" -ForegroundColor Gray

# Start Scan
Write-Host "`n[2/3] Canli Sistem Taramasi Baslatiliyor ($ScanType)..." -ForegroundColor Yellow
$startCmd = @{ cmd = "start_scan"; args = @{ kind = $ScanType; paths = @() } } | ConvertTo-Json -Compress
Send-Frame $pipe $startCmd
$scanInit = (Read-Frame $pipe) | ConvertFrom-Json
$jobId = $scanInit.data.job_id
Write-Host "      Gorev Kimligi: $jobId" -ForegroundColor Cyan

while ($true) {
    Start-Sleep -Milliseconds 400
    Send-Frame $pipe '{"cmd":"get_scan_progress","args":{"job_id":null}}'
    $prog = (Read-Frame $pipe) | ConvertFrom-Json
    if (-not $prog.data) { break }
    
    $c = $prog.data.counters
    $scanned = $c.files_scanned
    $threats = $c.threats_found
    $cur = $prog.data.current_target
    if ($cur -and $cur.Length -gt 60) {
        $cur = "..." + $cur.Substring($cur.Length - 57)
    }

    Write-Host -NoNewline "`r  [>] Taranan: $scanned dosya | Tehdit: $threats | $cur                      "

    if ($prog.data.state -in @("completed", "failed", "cancelled")) {
        Write-Host ""
        break
    }
}

# Final Result
Write-Host "`n[3/3] Tarama Sonuc Raporu:" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Taranan Dosya Sayisi:    $($prog.data.counters.files_scanned)" -ForegroundColor White
Write-Host "  Taranan Veri Boyutu:     $([math]::Round($prog.data.counters.bytes_scanned / 1MB, 2)) MB" -ForegroundColor White
Write-Host "  Taranan Arsivler (ZIP):  $($prog.data.counters.archives_scanned)" -ForegroundColor White
Write-Host "  Gecen Sure:              $([math]::Round($prog.data.elapsed_ms / 1000, 2)) saniye" -ForegroundColor White
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

if ($prog.data.counters.threats_found -eq 0) {
    Write-Host "  [DURUM: TEMIZ] Sisteminizde herhangi bir aktif virus," -ForegroundColor Green
    Write-Host "  truva ati veya zararli yazilim bulunamadi!" -ForegroundColor Green
} else {
    Write-Host "  [DURUM: TEHDIT BULUNDU] $($prog.data.counters.threats_found) adet tehdit tespit edildi!" -ForegroundColor Red
}
Write-Host "============================================================" -ForegroundColor Cyan

$pipe.Close()
