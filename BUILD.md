# AEGIS AI Security - Build Guide

This document details the build procedure for creating production-ready binaries, installers, and rule bundles for Windows 10 and 11 (x86_64).

---

## 🎯 Build Targets

| Component | Target Binary / Artifact | Build Tool | Profile |
|---|---|---|---|
| **Security Service** | `release/aegis-service.exe` | Cargo / Rust | Release (`opt-level = 3`, LTO) |
| **Desktop Web Assets** | `apps/desktop/dist/` | Vite + TypeScript | Production Minified |
| **Desktop Application** | `release/AEGIS AI Security.exe` | Tauri v2 CLI | Release NSIS Bundle |
| **Browser Shield** | `browser-extension/` | Chromium MV3 | Production Static Bundle |
| **Security Rules** | `release/rules/` | YARA-X / JSON | Offline Signatures |

---

## 📦 Step-by-Step Production Build

### 1. Build All Components (Automated)
The recommended way to build all release artifacts is via PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-release.ps1
```

This automated script performs:
1. Release compilation of `aegis-service.exe`.
2. Compiles and minifies the React 19 frontend into `apps/desktop/dist/`.
3. Invokes Tauri v2 to assemble the desktop binary and NSIS installer.
4. Copies static rules and signatures into the `release/` directory.
5. Computes SHA-256 hashes of all artifacts into `release/SHA256SUMS.txt`.

---

## ⚙️ Manual Build Steps

### A. Building the Security Service (`aegis-service.exe`)
```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo build --release -p aegis-service
```
The output binary will be located at:
`target\release\aegis-service.exe`

### B. Building the React Desktop Interface
```powershell
cd apps/desktop
npm install
npm run build
```
The compiled HTML, CSS, and JS bundles will be in:
`apps/desktop/dist`

### C. Building the Tauri Desktop Installer
```powershell
cd apps/desktop
npm run tauri build
```
Upon completion, the installer and standalone executable will be located in:
`apps/desktop/src-tauri/target/release/bundle/nsis/`

---

## 🔍 Troubleshooting Build Issues

1. **`link.exe` / MSVC Build Tools Missing**:
   Ensure you have installed Visual Studio Community or Visual C++ Build Tools with the "Desktop development with C++" workload. Run `check-environment.ps1` to verify.

2. **YARA-X Compilation & Memory Usage**:
   YARA-X uses Cranelift JIT which requires substantial compilation memory. Ensure at least 4 GB of free virtual memory during release builds.

3. **NSIS Bundling Notice**:
   If Tauri cannot locate an NSIS compiler, install NSIS via `winget install NSIS.NSIS` or run `build-release.ps1 -SkipTauriBundle` to stage the standalone binaries directly.

