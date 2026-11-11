# AEGIS AI Security

<p align="center">
  <img src="apps/desktop/public/logo.png" alt="AEGIS AI Security Logo" width="160" />
</p>

<p align="center">
  <strong>Next-Generation Local-First Endpoint Protection & AI Antivirus Suite (Windows 10/11)</strong><br />
  <em>Yeni Nesil Yerel Uç Nokta Koruması & AI Destekli Çok Dilli Antivirüs Güvenlik Paketi</em>
</p>

<p align="center">
  <a href="https://github.com/Kaankrl/AEGIS-Anti-Virus-AI/releases/latest"><img src="https://img.shields.io/badge/Download-AEGIS%20Setup%20v0.1.0-cyan?style=for-the-badge&logo=windows" alt="Download AEGIS Setup" /></a>
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20(64--bit)-blue?style=for-the-badge&logo=windows" alt="Platform Windows 10/11" />
  <img src="https://img.shields.io/badge/Languages-EN%20%7C%20TR%20%7C%20DE%20%7C%20ES%20%7C%20FR%20%7C%20RU-indigo?style=for-the-badge&logo=google-translate" alt="Multi-Language Supported" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Proprietary%20%2F%20AegisVerse-purple?style=for-the-badge" alt="License" /></a>
  <img src="https://img.shields.io/badge/VirusTotal-0%2F70%20Clean-brightgreen?style=for-the-badge&logo=virustotal" alt="VirusTotal Clean" />
</p>

---

## ⬇️ Download & Installation (Official Release)

You can download and deploy the latest official multi-language release of AEGIS AI Security immediately:

| Package / Download Link | Type | Size | Description |
|---|---|---|---|
| 🚀 **[AEGIS AI Security Setup 0.1.0.exe](https://github.com/Kaankrl/AEGIS-Anti-Virus-AI/releases/latest/download/AEGIS.AI.Security.Setup.0.1.0.exe)** | **Official Windows Installer** | ~130 MB | Automatic installer with desktop shortcut, splash screen, and multi-language setup wizard. |

> 🌐 **Multi-Language Support (EN, TR, DE, ES, FR, RU):**  
> The installer automatically prompts for your preferred language upon launch. All installation screens, license agreements, and the desktop UI seamlessly adapt to your selection.
> 
> 🛡️ **Integrated Web & YouTube Ad Shield:**  
> The companion browser extension (anti-malware link blocker and YouTube ad skipper for Brave, Chrome, and Edge) comes bundled inside the application and can be toggled on directly from the desktop dashboard.
> 
> 🔒 **Official SHA-256 Checksum Verification:**  
> `0D9930E8C2BE5961FD06ED61A3E85B522C2DE5663301E324C354EEC4AE5F6D13`

---

## 🚨 LEGAL NOTICE & ANTI-PIRACY STATEMENT (AEGISVERSE)

> [!WARNING]
> ### ⚖️ INTELLECTUAL PROPERTY & COPYRIGHT PROTECTION
> All source code, user interface designs, trademarks, brand assets, logos, heuristic detection models, and YARA-X rule sets contained in this repository are the exclusive intellectual property of **AegisVerse**.
> 
> **WHY IS THIS REPOSITORY PUBLIC?**  
> As an independent modern cybersecurity initiative, we believe in **100% transparency**. We open this codebase publicly so that security researchers, independent reverse-engineers, and users worldwide can inspect, audit, and verify that AEGIS contains **zero backdoors, zero telemetry, and zero hidden surveillance**.
>
> **STRICTLY PROHIBITED ACTIVITIES:**
> 1. Copying, stealing, rebranding, changing logos/names, or redistributing this software under any alternate author or organization name (**Rebranding / Cloning / Fork-scamming**).
> 2. Selling, renting, bundling, or commercially exploiting this software, whether in binary or source form, without an explicit commercial license from AegisVerse.
> 3. Disabling copyright notices, author attributions, or license terms.
>
> 🛑 **LEGAL CONSEQUENCES:**  
> Any unauthorized reproduction, commercial distribution, or trademark infringement will be subject to immediate global **DMCA Takedowns**, domain suspension notices, and civil litigation under international treaties including the **Berne Convention and WIPO**. Please review the complete **[LICENSE](LICENSE)** document for detailed terms.

---

## 🛡️ Architecture & Core Defense Engine

AEGIS operates with a **zero-cloud-telemetry, local-first** architecture. All scan computation, behavioral detection, heuristic evaluation, and quarantine management run 100% locally on your endpoint without requiring any cloud subscription or external API dependencies:

```
       +-----------------------------------------------------------+
       |         AEGIS AI Security Desktop UI (React 19 + Vite)    |
       |  - Multi-Language Engine (TR, EN, DE, ES, FR, RU)         |
       |  - Ambient Frameless Transparent Splash Screen            |
       |  - Real-Time IPC Bridge (Windows Named Pipe / RPC)        |
       +-----------------------------------------------------------+
                                   | IPC Bridge
       +-----------------------------------------------------------+
       |           AEGIS Core Background Protection Service        |
       |  - Multi-Engine YARA-X Scanner  - Real-Time File Watcher  |
       |  - Heuristic PE Binary Analyst  - Anti-Ransomware Shield  |
       |  - RAT & Spyware Process Hunter - Network Socket Monitor  |
       |  - Startup & Registry Guardian  - USB Removable Protector |
       |  - XOR-Encrypted Safe Vault     - YouTube Web Shield      |
       |  - Local AI Security Analyst    - Microsoft Defender Safe |
       +-----------------------------------------------------------+
```

---

## ⚡ Key Protection Capabilities

| Protection Layer | Technology & Mechanism | Functionality |
|---|---|---|
| **Multi-Engine Scanner** | YARA-X, PE Analysis, SHA-256 Hashes | Scans inside ZIP archives, executables, scripts, and high-risk directories with memory bounding. |
| **Real-Time File Watcher** | Windows `ReadDirectoryChangesW` | Monitors file writes in Downloads, Temp, and Startup directories to intercept threats instantly. |
| **Anti-Ransomware Shield** | 5-Second Sliding Window Entropy | Blocks suspicious background processes attempting high-frequency mass file encryption or modifications. |
| **RAT & Spyware Hunter** | Process Hierarchy & LOLBins Heuristics | Prevents office apps or browsers from launching hidden command shells (`powershell.exe`, `cmd.exe`). |
| **Web & YouTube Shield** | Manifest V3 Extension & Declarative Rules | 0ms automated YouTube ad skip, pop-under suppression, and known malicious URL filtering. |
| **Network & Socket Auditor** | `GetExtendedTcpTable` Live Mapping | Real-time inspection of active network connections mapped to their originating process IDs. |
| **Startup Guardian** | Registry (`Run` / `RunOnce`) & Folder Watch | Alerts and isolates unauthorized startup persistence entries automatically. |
| **USB Removable Media Guard** | `DRIVE_REMOVABLE` Hotplug Detection | Scans connected flash drives for malicious `autorun.inf` files, hidden shortcuts, and scripts. |
| **Encrypted Quarantine Vault** | Randomized 32-Byte XOR Encryption | Safely neutralizes malicious payloads on disk while preserving the option for user-verified restore. |
| **Defender Coexistence** | Windows Security Center Integration | Operates in harmony alongside Microsoft Defender; never disables or weakens native Windows protections. |

---

## 🤝 Native Windows Defender Harmony

AEGIS AI Security adheres to ethical defensive standards:
- **Never Disables Defender:** Microsoft Defender remains the primary system antivirus.
- **Respects UAC & SmartScreen:** Does not manipulate or bypass Windows User Account Control or SmartScreen.
- **Protects Critical OS Binaries:** Whitelist guards prevent accidental quarantine of core Windows binaries (`explorer.exe`, `svchost.exe`, `csrss.exe`, etc.).

---

## 💻 System Requirements

- **Operating System:** Windows 10 (Build 19041+) or Windows 11 (64-bit x64).
- **RAM:** Minimum 4 GB RAM (8 GB recommended).
- **Storage:** 500 MB free disk space.
- **Execution Mode:** Runs seamlessly in Standard User Mode; optional Windows Background Service utilizes Administrator elevation when needed.

---

## 🔒 Privacy Guarantee (Zero Cloud Telemetry)

- **100% Local Execution:** Your files, passwords, documents, and browsing habits are never uploaded to any remote server or third-party cloud AI.
- **No Covert Backdoors:** AEGIS does not feature remote administration tools, reverse shells, or telemetry trackers.
- **Encrypted Local Logs:** All security scan logs and audit trails remain encrypted in a local SQLite database on your machine.

---

<details>
<summary><strong>🇹🇷 Türkçe Özet ve Bilgilendirme (Click to expand Turkish Summary)</strong></summary>

### AEGIS AI Security - Yeni Nesil Yerel Uç Nokta Koruması

**AegisVerse** tarafından geliştirilen AEGIS AI Security; Windows 10 ve Windows 11 için bağımsız, yerel öncelikli (local-first) ve çok katmanlı bir antivirüs çözümüdür.

- **Neden Açık Kaynak?** Kullanıcılarımızın ve araştırmacıların yazılımda hiçbir casus yazılım, arka kapı veya gizli telemetri olmadığını bizzat denetleyebilmesi için şeffaflık ilkemiz gereği herkese açık paylaşılmıştır.
- **Çoklu Dil Desteği:** Kurulum sihirbazı ve masaüstü arayüzü; Türkçe, İngilizce, Almanca, İspanyolca, Fransızca ve Rusça olmak üzere 6 dilde tam uyumludur.
- **Fikri Mülkiyet Koruması:** Projenin izinsiz kopyalanması, isim değiştirilerek dağıtılması (rebranding) veya ticari satışı kesinlikle yasaktır ve uluslararası telif hakları (DMCA/WIPO) kapsamında korunmaktadır.

</details>

---

## 📄 License & Attribution

This project is licensed under the **AegisVerse Proprietary and Defense Community License**.  
For full legal terms, restrictions, and anti-piracy conditions, please refer to **[LICENSE](LICENSE)**.  
Third-party open-source components (YARA-X, SQLite, Tokio, React) are documented in **[LICENSES.md](LICENSES.md)**.

**Copyright © 2026 AegisVerse (`krlkaan@outlook.com`). All Rights Reserved.**
