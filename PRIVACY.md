# AEGIS AI Security - Privacy Policy & Guarantees

> **Zero Cloud Dependency. Zero Telemetry Exfiltration. 100% Local-First.**

---

## 1. Our Privacy Philosophy

AEGIS AI Security was designed to eliminate the invasive surveillance and telemetry practices common in modern security software. Traditional endpoint protection products often stream file hashes, process command lines, web browsing histories, and even full file payloads to cloud servers for remote analysis.

**AEGIS operates on a completely different model: your data never leaves your workstation.**

---

## 2. Telemetry Status: Strictly OFF by Default

- **Remote Telemetry**: **DISABLED**. AEGIS does not transmit telemetry, analytics, crash dumps, or usage metrics to any remote server.
- **Opt-In Only**: If community threat-sharing features are enabled in future versions, they will require explicit, cryptographic opt-in with full data anonymization.
- **No Third-Party Analytics**: No Google Analytics, Mixpanel, Sentry, or third-party webview trackers are included in the codebase.

---

## 3. What Data Is Stored Locally?

All persistent data is stored solely in a local SQLite database (`aegis.db`) located within your system profile directory:
- Privileged Service: `%ProgramData%\AegisAiSecurity\aegis.db`
- User Mode: `%LocalAppData%\AegisAiSecurity\aegis.db`

The local database contains:
1. **Scan Results**: Timestamp, duration, scanned file count, detected threat count.
2. **Threat Records**: File path, threat classification, severity, SHA-256 hash.
3. **Quarantine Records**: Original path, obfuscated storage path, SHA-256 integrity hash, quarantine timestamp.
4. **Security Events**: Chronological log of detection and remediation actions.
5. **Application Settings**: Language, theme, scan schedules, and protection toggles.

---

## 4. What Is NEVER Collected or Transmitted?

- Scanned file contents or document text.
- Usernames, passwords, or personal credentials.
- Browser browsing history or web searches.
- Hardware UUIDs or device fingerprinting records.
- Prompts or forensic queries submitted to the local AI Security Analyst.

---

## 5. User Control & Data Deletion

You have complete ownership over your security data:
- **Clear Security History**: You can clear the audit logs and event history at any time from the *Settings* or *Security History* pages.
- **Purge Quarantine**: You can permanently delete quarantined files and their records with a single click.
- **Complete Erasure**: Uninstalling AEGIS and deleting the `%ProgramData%\AegisAiSecurity` folder completely removes all records, database tables, and quarantined items with zero residual cloud trace.

