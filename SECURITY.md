# Security Policy

## Supported Versions

We take the security of AEGIS AI Security seriously. We actively support and patch the latest release branch:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability within AEGIS AI Security, please report it responsibly. **Do not create public GitHub issues or discussions for sensitive security findings.**

### How to Report:
1. Contact the security team via email: `krlkaan@outlook.com` (or file a GitHub Private Vulnerability Advisory).
2. Include the following details:
   - A detailed description of the vulnerability.
   - Exact steps to reproduce (proof of concept, benign test payloads only).
   - Affected AEGIS version, component, and Windows OS build.
   - Any potential mitigations you have identified.

### Vulnerability Response Timeline:
- **Initial Acknowledgement**: Within 48 hours of receipt.
- **Triage & Assessment**: Within 5 business days.
- **Fix & Advisory Release**: Coordinated with the reporter, typically within 30 days.

---

## Defensive Engineering Guarantees

AEGIS strictly complies with defensive software principles:
- **No Covert Access**: No hidden administrative backdoors or remote shell listeners.
- **No Insecure Privilege Escalation**: IPC named pipes enforce caller authorization. Unprivileged processes cannot command privileged services to execute arbitrary code.
- **Safe Quarantine**: All quarantined artifacts are obfuscated and rendered non-executable on disk.
- **OS Coexistence**: AEGIS never disables Microsoft Defender, Windows Firewall, or UAC.

