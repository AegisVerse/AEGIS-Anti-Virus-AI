# AEGIS AI Security - Testing & Quality Assurance Guide

This document describes the testing architecture, safe fixture generation, regression testing, and verification procedures for AEGIS AI Security.

---

## 🎯 Testing Philosophy

1. **No Live Destructive Malware**: Under no circumstances should live destructive malware, ransomware, or weaponized payloads be checked into this repository or executed during testing.
2. **Benign Test Fixtures**: All detection engines are tested using benign indicators:
   - Safe test strings (e.g. harmless EICAR-like strings or synthetic YARA matches).
   - Benign PE binaries compiled specifically to test section parsing, import tables, and entropy calculation.
   - Non-destructive fake ransomware file generators (creating dummy text files with `.locked` extensions in temporary scratch directories).
3. **Automated Verification**: All pull requests and release builds must pass automated unit, integration, and typecheck suites.

---

## 🚀 Running the Automated Test Suite

Execute all tests across the entire repository using the automated test runner:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-tests.ps1
```

### Component Breakdown:

#### 1. Backend Rust Workspace Tests:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-tests.ps1 -RustOnly
```
Covers:
- `aegis-common`: Path sanitization, SHA-256 streaming hash verification, Shannon entropy calculations.
- `aegis-storage`: Database migrations, WAL mode concurrency, corrupt database recovery, scan job history, quarantine transitions.
- `aegis-yara`: Compiles and runs YARA-X rules against harmless fixtures; verifies syntax isolation when malformed rules are encountered.
- `aegis-quarantine`: Full quarantine and restore cycle; verifies SHA-256 pre/post integrity and random 32-byte XOR obfuscation.
- `aegis-network`: Domain reputation lookups, wildcard subdomains, Windows Firewall command generation.

#### 2. Frontend React / TypeScript Tests:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-tests.ps1 -UiOnly
```
Covers:
- `typecheck`: Runs `tsc --noEmit` across all 18 pages and components.
- `vitest`: Runs store state transitions (language toggle, theme, active page, connection status) and localization dictionary parity between `tr.json` and `en.json`.

---

## 🔬 Manual Functional Verification

### Quarantine Vault Verification:
1. Create a dummy test file in a temporary folder:
   ```powershell
   "AEGIS-TEST-STRING-BENIGN" | Out-File "$env:TEMP\aegis_test.txt"
   ```
2. In the AEGIS UI, navigate to **Karantina Kasası (Quarantine)**.
3. Verify that the file can be quarantined, inspected, and safely restored with an identical SHA-256 hash.

### Real-Time Protection Verification:
1. Enable Real-Time Protection from the **Gerçek Zamanlı Koruma** page.
2. In a monitored directory, drop a text file matching a synthetic test rule.
3. Verify that the file is intercepted and an event is logged in the **Tehdit Merkezi (Threat Center)**.

