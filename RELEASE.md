# AEGIS AI Security - Release & Deployment Guide

This document describes the distribution packaging, Authenticode code-signing, verification, and deployment process for AEGIS AI Security.

---

## 📋 Release Checklist

Before distributing an AEGIS release package:

- [ ] All Rust unit tests pass (`cargo test --workspace`).
- [ ] Frontend TypeScript typecheck passes with 0 errors (`npm run typecheck`).
- [ ] Frontend Vitest test suite passes (`npm test`).
- [ ] Release binaries are compiled with optimizations (`build-release.ps1`).
- [ ] Binary architecture confirmed 64-bit AMD64 (`verify-release.ps1`).
- [ ] All static YARA rules compile without syntax errors.
- [ ] SHA-256 checksums are generated and validated (`SHA256SUMS.txt`).
- [ ] Coexistence checks verify Microsoft Defender remains active and unhindered.
- [ ] Quarantine restore cycle tested to ensure bit-for-bit file integrity.

---

## 🔏 Code Signing (Authenticode)

To prevent Windows SmartScreen untrusted warnings, production binaries must be digitally signed with a valid standard or EV Code Signing Certificate.

### Signing PowerShell Command (SignTool):
```powershell
signtool.exe sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a "release\aegis-service.exe"
signtool.exe sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a "release\AEGIS AI Security.exe"
```

### Self-Signed / Test Certificate Generation (Development Only):
```powershell
# Create test root and code signing certificate
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=AEGIS AI Security Test Signer" -CertStoreLocation "Cert:\CurrentUser\My"
Set-AuthenticodeSignature -FilePath "release\aegis-service.exe" -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
```

Verify the signature status via PowerShell:
```powershell
Get-AuthenticodeSignature -FilePath "release\aegis-service.exe"
```

---

## 📦 Release Artifact Structure

A production release package consists of:
```
release/
├── AEGIS-Setup-x64.exe           # NSIS Windows Installer
├── aegis-service.exe             # Privileged Windows Background Service / User Engine
├── SHA256SUMS.txt                # Cryptographic hashes of all artifacts
├── rules/
│   ├── yara/                     # YARA-X signature sets
│   ├── domains/                  # Local domain reputation blocklists
│   └── heuristics/               # PE heuristic definitions and known good hashes
└── browser-extension/            # Chromium Manifest V3 Web Shield package
```

---

## 🛡️ Service Installation & Management

The AEGIS background service can be registered or removed using the service binary itself (requires Administrator privileges):

### Install and Register Service:
```powershell
Start-Process -FilePath ".\release\aegis-service.exe" -ArgumentList "--install" -Verb RunAs
```

### Start Windows Service:
```powershell
Start-Service -Name "AegisAiSecurityService"
```

### Stop Windows Service:
```powershell
Stop-Service -Name "AegisAiSecurityService"
```

### Uninstall Service:
```powershell
Start-Process -FilePath ".\release\aegis-service.exe" -ArgumentList "--uninstall" -Verb RunAs
```

---

## 🔐 Verifying Release Artifacts

End users can verify download integrity using PowerShell:
```powershell
Get-FileHash -Path ".\release\aegis-service.exe" -Algorithm SHA256
```
Compare the output string with the official hash listed in `SHA256SUMS.txt`.

