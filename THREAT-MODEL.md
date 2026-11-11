# AEGIS AI Security - Threat Model & Security Architecture

This document defines the formal threat model, trust boundaries, attacker profiles, protected assets, and security mitigations of AEGIS AI Security.

---

## 1. System Assets & Trust Boundaries

```
+------------------------------------------------------------------------------------+
| UNTRUSTED ZONE                                                                    |
|  - Malicious files on disk (PE binaries, scripts, downloads, email attachments)    |
|  - Untrusted remote network hosts (C2 servers, phishing websites, tracker domains) |
|  - Untrusted removable media (USB thumb drives with autorun or weaponized scripts) |
+------------------------------------------------------------------------------------+
                                      |
                           [Boundary 1: Filesystem / Network]
                                      v
+------------------------------------------------------------------------------------+
| UNPRIVILEGED EXECUTION ENVIRONMENT                                                 |
|  - React 19 Frontend Webview (sandboxed in WebView2, no direct OS APIs)            |
|  - Chromium Web Shield Extension (Manifest V3 sandbox)                             |
|  - User-mode Named Pipe Client (`\\.\pipe\aegis-user-<SID>`)                       |
+------------------------------------------------------------------------------------+
                                      |
                     [Boundary 2: Named Pipe IPC with Framing]
                                      v
+------------------------------------------------------------------------------------+
| PRIVILEGED / SUPERVISED CORE (AEGIS Service / Engine)                              |
|  - Multi-Engine Scanner (YARA-X, PE Heuristics)                                    |
|  - Real-time Filesystem Watcher (`ReadDirectoryChangesW`)                          |
|  - Process Supervisor (`Toolhelp32`, `OpenProcess`, `SuspendThread`)               |
|  - Quarantine Vault (32-byte random XOR keyed store)                               |
|  - SQLite Database (WAL mode, parameterized queries)                               |
+------------------------------------------------------------------------------------+
                                      |
                     [Boundary 3: Documented Windows APIs]
                                      v
+------------------------------------------------------------------------------------+
| WINDOWS OPERATING SYSTEM (Trusted Platform)                                        |
|  - Microsoft Defender Antivirus                                                    |
|  - Windows Firewall & Advanced Security (`netsh advfirewall`)                      |
|  - Windows Security Center (WSC)                                                   |
|  - User Account Control (UAC) & SmartScreen                                        |
+------------------------------------------------------------------------------------+
```

---

## 2. Attacker Profiles & Attack Vectors

| Attacker Profile | Threat Description | Vector | Mitigation in AEGIS |
|---|---|---|---|
| **Ransomware Actor** | Rapid encryption or renaming of user documents. | Mass file renaming bursts, `.locked` extensions, ransom notes. | `RansomwareShield`: 5-second sliding window burst tracker; flags mass renaming and ransom note patterns. |
| **RAT / Infostealer** | Remote access trojan attempting persistence or credential dumping. | Office macro or browser spawning LOLBins (`powershell -enc`, `certutil`). | `RatHunter`: Process hierarchy heuristics; flags untrusted parent-child relationships. |
| **Phishing / C2 Network** | User deceived into visiting malicious domains or downloading payloads. | Malicious domain resolution, DNS lookups, phishing portals. | `DomainShield` & Browser Web Shield: Local blocklists and Windows Firewall IP rules. |
| **Malicious USB / Removable Media** | Weaponized removable drive plugged into endpoint. | `autorun.inf` files, hidden batch/VBS scripts on removable volumes. | `UsbGuardian`: Automatic enumeration of `DRIVE_REMOVABLE` drives and root inspection. |
| **Compromised Frontend / Webview** | Malicious injection or XSS inside the webview trying to execute arbitrary code. | Webview code injection or tainted IPC message. | Strict Tauri IPC isolation; webview has zero direct filesystem or shell access; strictly validated commands. |
| **Local Privilege Escalation (LPE)** | Local unprivileged malware attempting to abuse AEGIS service pipe to run code as SYSTEM. | Malformed named pipe messages, path traversal in quarantine calls. | Authenticated Named Pipe with access control; paths strictly validated (`validate_user_path`); no arbitrary command execution. |

---

## 3. Specific Attack Mitigations

### 3.1 Path Traversal & Symlink Attacks
- **Threat**: An attacker passes `C:\Windows\System32\..\..\something` or a directory junction/symlink to overwrite or delete critical system files.
- **Mitigation**: The `validate_user_path` helper resolves canonical paths, rejects paths outside allowed scan roots, and hardcodes protection for critical Windows system directories (`System32`, `SysWOW64`, `ProgramData\Microsoft`, `Windows`).

### 3.2 IPC Injection & Deserialization Vulnerabilities
- **Threat**: Passing oversized payloads or crafted JSON to cause buffer overflows or arbitrary code execution.
- **Mitigation**: Rust's memory safety prevents memory corruption. The IPC transport frames messages with a 4-byte little-endian length prefix and enforces strict message limits (16 MB maximum envelope). Payloads are strongly typed and parsed via `serde_json` with unknown fields rejected or safely ignored.

### 3.3 Quarantine Tampering & Re-infection
- **Threat**: Quarantined malware remains executable on disk, or an attacker modifies the quarantine record to restore malware to another target location.
- **Mitigation**: The Quarantine Vault obfuscates files using a 32-byte cryptographic random XOR key, rendering PE headers and machine code inert. Both pre-quarantine and post-quarantine SHA-256 hashes are computed and verified before any restore operation is authorized.

### 3.4 Denial of Service (Zip Bombs)
- **Threat**: Scanning a 42.zip or recursive nested archive consumes all CPU and memory.
- **Mitigation**: The `ArchiveLimits` structure strictly bounds extraction: max 200 MB uncompressed, max 5,000 files, max 5 nested levels. Extraction immediately halts if thresholds are exceeded.

---

## 4. Explicit Non-Goals & Boundary Declarations

1. **No Kernel Drivers / ELAM**: AEGIS operates purely in user mode using documented Windows Win32 and Security APIs. It does not install third-party kernel filter drivers.
2. **Never Disable Defender**: AEGIS does not register as an exclusive antivirus provider to disable Microsoft Defender. Both engines coexist peacefully.
3. **No Offensive Tools**: AEGIS is strictly defensive; it does not contain penetration testing tools, offensive exploitation modules, or surveillance capabilities.

