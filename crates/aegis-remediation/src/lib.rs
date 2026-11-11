//! Threat remediation policy engine and safety authorization.

use aegis_common::error::{AegisError, Result};
use aegis_common::types::*;
use aegis_quarantine::QuarantineVault;
use aegis_storage::Storage;
use chrono::Utc;
use std::path::Path;
use std::sync::Arc;

pub struct RemediationEngine {
    storage: Arc<Storage>,
    vault: Arc<QuarantineVault>,
}

impl RemediationEngine {
    pub fn new(storage: Arc<Storage>, vault: Arc<QuarantineVault>) -> Self {
        Self { storage, vault }
    }

    /// Execute user or policy action on a detected threat.
    pub fn handle_threat_action(&self, threat_id: &str, action: ThreatAction) -> Result<ThreatRecord> {
        let mut threat = self.storage.get_threat(threat_id)?
            .ok_or_else(|| AegisError::NotFound(format!("threat {threat_id}")))?;

        match action {
            ThreatAction::Quarantine => {
                let path = Path::new(&threat.path);
                let _ = self.vault.quarantine_file(path, Some(&threat), Some("Remediated via Threat Center"))?;
                threat.status = ThreatStatus::Quarantined;
            }
            ThreatAction::Allow => {
                self.storage.set_threat_status(threat_id, ThreatStatus::Allowed)?;
                threat.status = ThreatStatus::Allowed;
                let _ = self.storage.audit("user", "allow_threat", Some(&threat.path), true, "success", None);
            }
            ThreatAction::Ignore => {
                self.storage.set_threat_status(threat_id, ThreatStatus::Ignored)?;
                threat.status = ThreatStatus::Ignored;
                let _ = self.storage.audit("user", "ignore_threat", Some(&threat.path), true, "success", None);
            }
        }

        threat.updated_at = Utc::now();
        Ok(threat)
    }

    /// Safely suspend a process (e.g. suspected ransomware or RAT), refusing critical system processes.
    pub fn suspend_process(&self, pid: u32, confirm: bool) -> Result<u32> {
        if !confirm {
            return Err(AegisError::Policy("Explicit user confirmation required to suspend process".into()));
        }

        // Prevent suspending critical Windows PIDs (0, 4)
        if pid <= 4 {
            return Err(AegisError::Policy(format!("Refusing to suspend system PID {pid}")));
        }

        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::*;
            use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
            use windows_sys::Win32::System::Threading::*;

            let mut count = 0;
            unsafe {
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if snapshot == INVALID_HANDLE_VALUE {
                    return Err(AegisError::Internal("failed to snapshot threads".into()));
                }

                let mut te: THREADENTRY32 = std::mem::zeroed();
                te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

                if Thread32First(snapshot, &mut te) != 0 {
                    loop {
                        if te.th32OwnerProcessID == pid {
                            let h_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
                            if !h_thread.is_null() {
                                SuspendThread(h_thread);
                                CloseHandle(h_thread);
                                count += 1;
                            }
                        }
                        if Thread32Next(snapshot, &mut te) == 0 {
                            break;
                        }
                    }
                }
                CloseHandle(snapshot);
            }

            let _ = self.storage.audit(
                "user",
                "suspend_process",
                Some(&format!("PID {}", pid)),
                true,
                "success",
                Some(&format!("Suspended {} threads", count)),
            );

            Ok(count)
        }

        #[cfg(not(windows))]
        {
            Ok(0)
        }
    }

    /// Resume a previously suspended process.
    pub fn resume_process(&self, pid: u32) -> Result<u32> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::*;
            use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
            use windows_sys::Win32::System::Threading::*;

            let mut count = 0;
            unsafe {
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if snapshot == INVALID_HANDLE_VALUE {
                    return Err(AegisError::Internal("failed to snapshot threads".into()));
                }

                let mut te: THREADENTRY32 = std::mem::zeroed();
                te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

                if Thread32First(snapshot, &mut te) != 0 {
                    loop {
                        if te.th32OwnerProcessID == pid {
                            let h_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
                            if !h_thread.is_null() {
                                ResumeThread(h_thread);
                                CloseHandle(h_thread);
                                count += 1;
                            }
                        }
                        if Thread32Next(snapshot, &mut te) == 0 {
                            break;
                        }
                    }
                }
                CloseHandle(snapshot);
            }

            let _ = self.storage.audit(
                "user",
                "resume_process",
                Some(&format!("PID {}", pid)),
                true,
                "success",
                Some(&format!("Resumed {} threads", count)),
            );

            Ok(count)
        }

        #[cfg(not(windows))]
        {
            Ok(0)
        }
    }
}
