# AEGIS AI Security - Developer Guide

This document describes how to set up, build, test, and contribute to the AEGIS AI Security codebase.

---

## 🛠️ Prerequisites

To build and run AEGIS AI Security on Windows 10 or 11, ensure you have the following free tools installed:

1. **Operating System**: Windows 10 (Build 19041+) or Windows 11 (64-bit AMD64).
2. **Rust Toolchain**: Stable Rust 1.80+ (recommended: Rust 1.99.1+) with `rustc`, `cargo`, `rustfmt`, and `clippy`.
3. **Node.js & npm**: Node.js v18.0+ (recommended: Node.js v20+ or v26+) and npm v10+.
4. **C++ Build Tools**: Microsoft Visual C++ Build Tools or Visual Studio Community with the "Desktop development with C++" workload (provides `link.exe` and Windows SDK headers).
5. **Microsoft Edge WebView2**: Present by default on modern Windows.

---

## ⚡ Quick Environment Verification

Verify your local toolchain using the automated verification script:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-environment.ps1
```

If any required item is reported missing, install it from its official free vendor website:
- Rust: https://rustup.rs/
- Node.js: https://nodejs.org/
- Visual Studio Build Tools: https://visualstudio.microsoft.com/visual-cpp-build-tools/

---

## 🚀 Development Workflow

### 1. Initial Workspace Setup
Run the automated initialization script to verify tools, install desktop npm dependencies, and compile the workspace crates:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup-dev.ps1
```

### 2. Running the Development Server
You can launch the Vite frontend development server:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1
```
Open http://localhost:1420 in your browser to inspect and interact with the UI.

To launch the development server alongside an active user-mode security engine:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -WithEngine
```

To run full Tauri desktop integration mode:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -TauriDev
```

---

## 🧪 Testing Guidelines

AEGIS enforces strict testing standards across both backend engines and frontend user interface:

### Running All Tests
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-tests.ps1
```

### Running Rust Workspace Tests Only
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-tests.ps1 -RustOnly
# Or directly via cargo:
cargo test --workspace
```

### Running Frontend Tests & Typecheck Only
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-tests.ps1 -UiOnly
```

### Writing New Unit Tests
- **Rust Engine Crates**: Add unit tests inside a `#[cfg(test)] mod tests` block at the bottom of the relevant module file or in a separate `tests/` integration test directory. Always test edge cases (corrupt files, non-PE files, path traversal attempts, missing registry keys).
- **Frontend Components & Stores**: Add Vitest tests in `apps/desktop/src/__tests__/`. Verify localization key parity whenever new text strings are added to `locales/tr.json` or `locales/en.json`.

---

## 🔒 Security & Code Standards

All contributors and automated agents must adhere to the following non-negotiable security principles:

1. **Defensive Software Only**: Never write code that facilitates unauthorized persistence, process injection, credential dumping, or covert remote administration.
2. **Never Weaken Windows Protections**: Never disable or modify Microsoft Defender, Windows Firewall, UAC, or SmartScreen.
3. **Safe Coexistence**: Treat Microsoft Defender as a primary or cooperative security provider.
4. **System File Protection**: All file operations (quarantine, deletion, modification) MUST check against critical Windows directories (`System32`, `SysWOW64`, `explorer.exe`, etc.) to prevent OS corruption.
5. **Transparent Claims**: Never report a feature or AI model as active unless backed by a functioning, verified implementation. If model weights are not loaded, report `"AI model is not installed"`.
6. **No Cloud Dependency**: Never introduce external paid APIs or telemetry services. All features must be 100% functional offline and locally.

