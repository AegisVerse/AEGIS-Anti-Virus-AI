//! Process enumeration and memory usage monitoring for Windows.

use aegis_behavior::RatHunter;
use aegis_common::types::*;
use aegis_heuristics::verify_file_signature;
use aegis_storage::Storage;
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

pub struct ProcessMonitor {
    storage: Arc<Storage>,
    rat_hunter: Arc<RatHunter>,
}

impl ProcessMonitor {
    pub fn new(storage: Arc<Storage>, rat_hunter: Arc<RatHunter>) -> Self {
        Self { storage, rat_hunter }
    }

    /// Enumerate all running processes with ancestry, commandline, and memory metrics.
    pub fn snapshot(&self) -> Vec<ProcessInfo> {
        #[cfg(windows)]
        {
            self.snapshot_windows()
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    #[cfg(windows)]
    fn snapshot_windows(&self) -> Vec<ProcessInfo> {
        use windows_sys::Win32::Foundation::*;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        use windows_sys::Win32::System::ProcessStatus::*;
        use windows_sys::Win32::System::Threading::*;

        let mut processes = Vec::new();
        let mut parent_map = HashMap::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return processes;
            }

            let mut pe: PROCESSENTRY32W = std::mem::zeroed();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut pe) != 0 {
                loop {
                    let pid = pe.th32ProcessID;
                    let ppid = pe.th32ParentProcessID;
                    let name_len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len());
                    let name = String::from_utf16_lossy(&pe.szExeFile[..name_len]);

                    parent_map.insert(pid, (name.clone(), ppid));

                    let critical = is_critical_process(&name);

                    // Try to query full path & working set
                    let mut path = None;
                    let mut working_set = None;

                    let h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                    if !h_proc.is_null() {
                        let mut buf = [0u16; 1024];
                        let mut size = buf.len() as u32;
                        if QueryFullProcessImageNameW(h_proc, 0, buf.as_mut_ptr(), &mut size) != 0 {
                            path = Some(String::from_utf16_lossy(&buf[..size as usize]));
                        }

                        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                        if K32GetProcessMemoryInfo(h_proc, &mut pmc, pmc.cb) != 0 {
                            working_set = Some(pmc.WorkingSetSize as u64);
                        }

                        CloseHandle(h_proc);
                    }

                    let sig = path.as_ref().map(|p| verify_file_signature(&PathBuf::from(p)));

                    processes.push(ProcessInfo {
                        pid,
                        ppid,
                        name,
                        path,
                        command_line: None,
                        signature: sig,
                        parent_name: None,
                        session_id: None,
                        working_set_bytes: working_set,
                        first_seen: Utc::now(),
                        flags: Vec::new(),
                        critical,
                    });

                    if Process32NextW(snapshot, &mut pe) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
        }

        // Fill parent_name from parent_map and evaluate RAT hunter
        for proc in &mut processes {
            if let Some((pname, _)) = parent_map.get(&proc.ppid) {
                proc.parent_name = Some(pname.clone());
            }
            // Check for RAT / Trojan execution patterns
            self.rat_hunter.analyze_process(proc);
        }

        processes
    }
}

/// System critical processes that must never be terminated by the security product.
pub fn is_critical_process(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "system"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "services.exe"
            | "lsass.exe"
            | "svchost.exe"
            | "fontdrvhost.exe"
            | "dwm.exe"
            | "memory compression"
            | "registry"
            | "winlogon.exe"
            | "explorer.exe"
    )
}
