# AEGIS AI Security - Known Limitations & Transparency Report

In accordance with our core security principles, AEGIS AI Security never exaggerates detection capabilities or claims total protection against all malware. This document transparently details the technical boundaries and known constraints of the application.

---

## 1. User-Mode Architecture vs. Kernel / ELAM Drivers

- **Constraint**: AEGIS operates purely in user mode (as an unprivileged desktop client and a supervised Windows Background Service). It does not include an Early Launch Anti-Malware (ELAM) driver or a third-party kernel filesystem minifilter driver.
- **Impact**: AEGIS cannot intercept kernel-level rootkits or hypervisor-based implants operating at Ring 0. 
- **Mitigation & Coexistence**: AEGIS relies on and coexists with **Microsoft Defender**, which provides native kernel-level ELAM and cloud-backed driver protection. AEGIS acts as an advanced user-mode defense and behavioral intelligence layer.

---

## 2. Protected Processes (PPL) & Process Suspension

- **Constraint**: Windows Protected Process Light (PPL) processes (such as `csrss.exe`, `lsass.exe`, `services.exe`, and Microsoft Defender services) cannot be opened with `PROCESS_SUSPEND_RESUME` or terminated by any user-mode service without specialized kernel trust.
- **Impact**: AEGIS will deliberately refuse to suspend or terminate critical Windows system processes or processes protected by PPL.
- **Safety Benefit**: This prevents stability issues or malicious attempts to cause a Blue Screen of Death (BSOD) by tampering with core operating system components.

---

## 3. Local AI Model Requirements

- **Constraint**: The local AI security classifier relies on pre-trained ONNX neural network weights (`models/aegis_pe_classifier.onnx`).
- **Status When Absent**: When the model weights are not present on the endpoint, AEGIS transparently reports:
  > `"AI sınıflandırma modeli henüz kurulmadı."` / `"AI classification model is not installed."`
- **Integrity Guarantee**: The application will **never** display fake AI confidence scores or fictional threat predictions. The deterministic heuristic and YARA engines continue to provide complete coverage.

---

## 4. Archive Decompression Bounds

- **Constraint**: To defend against decompression bombs (Zip Bombs), archive inspection enforces strict limits:
  - Maximum uncompressed size: **200 MB**
  - Maximum file count per archive: **5,000 files**
  - Maximum recursion depth: **5 nested layers**
- **Impact**: Excessively large or deeply nested archives beyond these limits are partially inspected or flagged for manual user review.

---

## 5. Network Traffic Filtering Scope

- **Constraint**: AEGIS Domain Shield performs DNS and IP-level firewall blocking via Windows Firewall APIs (`netsh advfirewall`) and the Manifest V3 browser extension. It does not perform deep packet inspection (DPI) or man-in-the-middle SSL interception on encrypted HTTPS traffic at the socket layer.
- **Privacy Benefit**: This design guarantees that your encrypted HTTPS sessions, personal banking passwords, and TLS certificates are never decrypted or inspected on your machine.

