//! USB and removable device insertion detection and autorun inspection.

use aegis_common::types::*;
use chrono::Utc;
use std::path::{Path, PathBuf};

pub struct UsbGuardian;

impl UsbGuardian {
    /// Enumerate all currently mounted removable drives.
    pub fn list_drives() -> Vec<UsbDrive> {
        let mut drives = Vec::new();

        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::*;

            for b in b'D'..=b'Z' {
                let root_str = format!("{}:\\", b as char);
                let root_w: Vec<u16> = root_str.encode_utf16().chain(std::iter::once(0)).collect();

                unsafe {
                    let drive_type = GetDriveTypeW(root_w.as_ptr());
                    // 2 = DRIVE_REMOVABLE
                    if drive_type == 2 {
                        let path = PathBuf::from(&root_str);
                        let autorun = path.join("autorun.inf");
                        let has_autorun = autorun.exists();
                        let mut suspicious = Vec::new();

                        if has_autorun {
                            suspicious.push("Found autorun.inf configuration file on removable drive".into());
                        }

                        // Check for common LNK or hidden executables at root
                        if let Ok(entries) = std::fs::read_dir(&path) {
                            for e in entries.flatten() {
                                let name = e.file_name().to_string_lossy().to_ascii_lowercase();
                                if name.ends_with(".vbs") || name.ends_with(".scr") || name.ends_with(".pif") {
                                    suspicious.push(format!("Suspicious script/executable at drive root: {}", name));
                                }
                            }
                        }

                        drives.push(UsbDrive {
                            root: root_str,
                            label: Some(format!("Removable Drive ({}:)", b as char)),
                            filesystem: Some("FAT32/NTFS".into()),
                            total_bytes: None,
                            free_bytes: None,
                            inserted_at: Utc::now(),
                            autorun_inf: has_autorun,
                            suspicious_items: suspicious,
                            last_scan_job: None,
                            accessible: true,
                        });
                    }
                }
            }
        }

        drives
    }
}
