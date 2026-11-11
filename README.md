# AEGIS AI Security

> **Next-Generation Local-First Endpoint Protection & Antivirus for Windows 10/11**  
> *Defensive, Legitimate, Privacy-Respecting, Zero-Subscription Security.*

---

## 🛡️ Project Overview

**AEGIS AI Security** is a native Windows 10/11 endpoint security suite engineered for high-performance defensive protection without reliance on proprietary cloud services, telemetry exfiltration, or paid subscription models.

AEGIS runs entirely on your local machine. It combines signature scanning via **YARA-X**, deep Portable Executable (PE) structural heuristics, behavioral ransomware and RAT monitoring, process-to-socket network auditing, registry persistence guards, and local AI threat assessment into a unified, low-overhead platform.

```
       +-----------------------------------------------------------+
       |           AEGIS AI Security Desktop UI (React 19)         |
       +-----------------------------------------------------------+
                                   | Tauri v2 IPC
       +-----------------------------------------------------------+
       |               AEGIS Desktop Bridge (Rust)                 |
       +-----------------------------------------------------------+
                                   | Named Pipe (\\.\pipe\aegis-ai-security.v1)
       +-----------------------------------------------------------+
       |            AEGIS Background Service / User Engine         |
       |  - YARA-X Engine       - Real-Time Filesystem Watcher     |
       |  - PE Heuristics       - Ransomware Sliding-Window Shield |
       |  - RAT & LOLBins Guard - Process & Network Sentinel       |
       |  - Startup Guardian    - Removable USB Drive Inspector    |
       |  - Quarantine Vault    - Local SQLite Storage (WAL Mode)  |
       |  - Local AI Analyst    - Windows Defender Coexistence     |
       +-----------------------------------------------------------+
```

---

## ⚡ Key Capabilities

| Protection Layer | Technology & Implementation | Description |
|---|---|---|
| **Multi-Engine Scanner** | YARA-X, PE Analysis, Hashes | Deep scanning with recursive ZIP archive inspection and rate-limited chunking. |
| **Real-Time Guard** | Windows `ReadDirectoryChangesW` (`notify`) | Debounced on-create/on-modify threat interception for high-risk system paths. |
| **Ransomware Shield** | 5-Second Sliding Window Burst Tracker | Monitors mass file renaming/modification bursts and known ransom note naming patterns. |
| **RAT & Spyware Hunter** | Process Hierarchy & LOLBins Heuristics | Flags Office/Browser processes spawning `powershell.exe`, `cmd.exe`, or credential-dumping tools. |
| **Memory Monitoring** | Windows Toolhelp32 Snapshotting | Tracks suspicious memory working sets, module injections, and process-to-parent hierarchies. |
| **Network Sentinel** | `GetExtendedTcpTable` Socket Mapping | Live inspection of open TCP/UDP sockets mapped to responsible PIDs, image paths, and remote IPs. |
| **Domain & Web Shield** | Local Blocklists & Manifest V3 Extension | Zero-cloud domain reputation filtering, anti-phishing, tracker blocking, and Windows Firewall rules. |
| **Startup Guardian** | Windows Registry & Startup Folder | Real-time monitoring of HKCU/HKLM `Run`/`RunOnce` keys with automatic pre-modification snapshots. |
| **USB Security** | Windows Drive Type Notification | Automatic enumeration of `DRIVE_REMOVABLE` media; blocks `autorun.inf` and suspicious root scripts. |
| **Secure Quarantine** | 32-Byte Keyed Obfuscation Vault | Neutralizes malicious binaries with SHA-256 pre/post integrity verification and atomic restore. |
| **Local AI Analyst** | Grounded Deterministic & Local LLM | PE feature analysis with honest fallback when weights are absent; zero hallucinated telemetry. |
| **Coexistence** | Windows Security Center Integration | Complements Microsoft Defender, Windows Firewall, and UAC without weakening OS policies. |

---

## 🤝 Safe Coexistence with Microsoft Defender

AEGIS AI Security is designed from the ground up to **coexist safely** with native Windows security features:

- **Never Disables Defender**: Microsoft Defender Antivirus remains active as the primary or complementary provider.
- **Never Alters UAC or SmartScreen**: System integrity policies and tamper protection are preserved.
- **Protects System Files**: Hardcoded safeguards prevent AEGIS from quarantining or modifying critical Windows system binaries (`ntoskrnl.exe`, `explorer.exe`, `svchost.exe`, `csrss.exe`, etc.).

---

## 💻 System Requirements

- **Operating System**: Windows 10 (Build 19041+) or Windows 11 (64-bit AMD64).
- **Runtime**: Microsoft Edge WebView2 (installed by default on modern Windows).
- **Hardware**: 4 GB RAM minimum (8 GB recommended), 500 MB free disk space.
- **Privileges**: Runs out-of-the-box in **User Mode**; optional **Windows Background Service** mode requires Administrator privileges during service installation.

---

## 🚀 Quick Start Guide

### 1. Developer Setup
Clone the repository and run the automated setup script in PowerShell:
```powershell
.\scripts\setup-dev.ps1
```

### 2. Running in Development Mode
Start the local user-mode engine alongside the React/Vite development server:
```powershell
.\scripts\dev.ps1 -WithEngine
```

### 3. Running All Tests
Execute the full test suite (Rust workspace unit tests, TypeScript typechecks, and Vitest suite):
```powershell
.\scripts\run-tests.ps1
```

### 4. Building Production Release
Build optimized release binaries, stage rules, and generate SHA-256 checksums:
```powershell
.\scripts\build-release.ps1
```

Verify release integrity:
```powershell
.\scripts\verify-release.ps1
```

---

## 📁 Repository Structure

```
├── apps/
│   └── desktop/               # Tauri v2 desktop UI (React 19 + TypeScript + Tailwind)
├── crates/
│   ├── aegis-common/          # Shared types, error definitions, streaming SHA-256
│   ├── aegis-storage/         # SQLite storage engine with WAL mode and migrations
│   ├── aegis-yara/            # Official yara-x scanner engine integration
│   ├── aegis-heuristics/      # PE parsing, entropy, section analysis, Authenticode
│   ├── aegis-scanner/         # Multi-engine scanner pipeline and archive inspector
│   ├── aegis-quarantine/      # Obfuscated quarantine vault and safe restoration
│   ├── aegis-behavior/        # RAT hunter, ransomware sliding-window heuristics
│   ├── aegis-monitor/         # Real-time filesystem watcher and process supervisor
│   ├── aegis-network/         # Socket mapping, domain reputation, firewall rules
│   ├── aegis-audit/           # System audit, startup persistence, USB guardian
│   ├── aegis-ai/              # Local PE classifier and grounded threat analyst
│   ├── aegis-remediation/     # Safe remediation, process suspension, allowlisting
│   ├── aegis-updater/         # Rule-pack updates and version tracker
│   ├── aegis-ipc/             # Named pipe protocol, framing, and command dispatcher
│   └── aegis-service/         # Windows Background Service & user-mode host
├── browser-extension/         # Chromium Manifest V3 Web Shield extension
├── rules/                     # YARA rules, domain blocklists, heuristic definitions
├── scripts/                   # PowerShell development and release automation
└── docs/                      # Technical specifications and forensic references
```

---

## 🔒 Security & Privacy Policy

AEGIS is strictly open and defensive software:
- **No Remote Telemetry**: Telemetry defaults strictly to OFF; no personal data, scanned file paths, or file contents leave your workstation.
- **No Covert Remote Access**: No backdoors, remote shells, or hidden services.
- **Audit Logs**: All system actions (scans, quarantine, process suspension) are logged locally in SQLite.

---

## 📄 License

AEGIS AI Security is distributed under the [MIT License](LICENSES.md).  
Third-party licenses and acknowledgments are documented in [LICENSES.md](LICENSES.md).

