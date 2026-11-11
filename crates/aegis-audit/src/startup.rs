//! Windows startup and persistence monitoring (Registry Run/RunOnce, Startup folders).

use aegis_common::error::{AegisError, Result};
use aegis_common::types::*;
use aegis_heuristics::verify_file_signature;
use aegis_storage::{StartupBackupRow, Storage};
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

pub struct StartupGuardian {
    storage: Arc<Storage>,
}

impl StartupGuardian {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    /// List all observed startup entries across registry and startup folders.
    pub fn list_items(&self) -> Vec<StartupItem> {
        let mut items = Vec::new();

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Registry::*;

            // 1. HKCU\Software\Microsoft\Windows\CurrentVersion\Run
            Self::read_registry_run(
                HKEY_CURRENT_USER,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                StartupLocation::RegistryRun,
                "user",
                &mut items,
            );

            // 2. HKLM\Software\Microsoft\Windows\CurrentVersion\Run
            Self::read_registry_run(
                HKEY_LOCAL_MACHINE,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                StartupLocation::RegistryRun,
                "machine",
                &mut items,
            );
        }

        // 3. User Startup Folder
        if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            let startup_dir = PathBuf::from(user_profile)
                .join("AppData")
                .join("Roaming")
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup");

            Self::read_startup_folder(&startup_dir, "user", &mut items);
        }

        items
    }

    #[cfg(windows)]
    fn read_registry_run(
        root: windows_sys::Win32::System::Registry::HKEY,
        subkey_str: &str,
        location: StartupLocation,
        scope: &str,
        items: &mut Vec<StartupItem>,
    ) {
        use windows_sys::Win32::System::Registry::*;

        let subkey: Vec<u16> = subkey_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey: HKEY = std::ptr::null_mut();
        unsafe {
            if RegOpenKeyExW(root, subkey.as_ptr(), 0, KEY_READ, &mut hkey) == 0 {
                let mut index = 0;
                loop {
                    let mut val_name = [0u16; 260];
                    let mut val_len = val_name.len() as u32;
                    let mut val_type = 0u32;
                    let mut data = [0u8; 1024];
                    let mut data_len = data.len() as u32;

                    let ret = RegEnumValueW(
                        hkey,
                        index,
                        val_name.as_mut_ptr(),
                        &mut val_len,
                        std::ptr::null_mut(),
                        &mut val_type,
                        data.as_mut_ptr(),
                        &mut data_len,
                    );

                    if ret != 0 {
                        break;
                    }

                    let name = String::from_utf16_lossy(&val_name[..val_len as usize]);
                    let command = if val_type == REG_SZ || val_type == REG_EXPAND_SZ {
                        let u16_slice = std::slice::from_raw_parts(data.as_ptr() as *const u16, (data_len / 2) as usize);
                        let len = u16_slice.iter().position(|&c| c == 0).unwrap_or(u16_slice.len());
                        String::from_utf16_lossy(&u16_slice[..len])
                    } else {
                        String::new()
                    };

                    let exe_path = Self::extract_executable_path(&command);
                    let sig = exe_path.as_ref().map(|p| verify_file_signature(&PathBuf::from(p)));

                    let assessment = if let Some(s) = &sig {
                        if s.is_trusted() {
                            Assessment::Trusted
                        } else {
                            Assessment::Unknown
                        }
                    } else {
                        Assessment::Unknown
                    };

                    let id = format!("{}_{}_{}", scope, location as u8, name);

                    items.push(StartupItem {
                        id,
                        location,
                        scope: scope.to_string(),
                        container: subkey_str.to_string(),
                        name,
                        command,
                        executable_path: exe_path,
                        signature: sig,
                        modified_at: None,
                        first_seen: Utc::now(),
                        assessment,
                        indicators: Vec::new(),
                        can_disable: true,
                        is_new: false,
                    });

                    index += 1;
                }
                RegCloseKey(hkey);
            }
        }
    }

    fn read_startup_folder(dir: &Path, scope: &str, items: &mut Vec<StartupItem>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    let sig = verify_file_signature(&path);
                    let is_trusted = sig.is_trusted();

                    items.push(StartupItem {
                        id: format!("{}_folder_{}", scope, name),
                        location: StartupLocation::StartupFolder,
                        scope: scope.to_string(),
                        container: dir.to_string_lossy().to_string(),
                        name: name.clone(),
                        command: path.to_string_lossy().to_string(),
                        executable_path: Some(path.to_string_lossy().to_string()),
                        signature: Some(sig),
                        modified_at: None,
                        first_seen: Utc::now(),
                        assessment: if is_trusted { Assessment::Trusted } else { Assessment::Unknown },
                        indicators: Vec::new(),
                        can_disable: true,
                        is_new: false,
                    });
                }
            }
        }
    }

    fn extract_executable_path(cmd: &str) -> Option<String> {
        let trimmed = cmd.trim();
        if trimmed.starts_with('"') {
            if let Some(end) = trimmed[1..].find('"') {
                return Some(trimmed[1..=end].to_string());
            }
        }
        trimmed.split_whitespace().next().map(str::to_string)
    }

    /// Disable a startup item, preserving a backup for safe recovery.
    pub fn disable_item(&self, item_id: &str, confirm: bool) -> Result<StartupBackup> {
        if !confirm {
            return Err(AegisError::Policy("Confirmation required to disable startup entry".into()));
        }

        let items = self.list_items();
        let item = items.into_iter().find(|i| i.id == item_id)
            .ok_or_else(|| AegisError::NotFound(format!("startup item {item_id}")))?;

        let backup = StartupBackup {
            id: Uuid::new_v4().to_string(),
            item_name: item.name.clone(),
            container: item.container.clone(),
            value: item.command.clone(),
            created_at: Utc::now(),
            restored: false,
        };

        let row = StartupBackupRow {
            backup: backup.clone(),
            item_id: item.id.clone(),
            hive: item.scope.clone(),
            value_name: item.name.clone(),
            value_type: 1, // REG_SZ
        };

        self.storage.insert_startup_backup(&row)?;

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Registry::*;
            let root = if item.scope == "user" { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };
            let subkey: Vec<u16> = item.container.encode_utf16().chain(std::iter::once(0)).collect();
            let val_name: Vec<u16> = item.name.encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExW(root, subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) == 0 {
                    RegDeleteValueW(hkey, val_name.as_ptr());
                    RegCloseKey(hkey);
                }
            }
        }

        let _ = self.storage.audit(
            "user",
            "disable_startup",
            Some(&item.name),
            true,
            "success",
            Some(&format!("Backed up as {}", backup.id)),
        );

        Ok(backup)
    }

    /// Restore a previously disabled startup item from backup.
    pub fn restore_item(&self, backup_id: &str) -> Result<StartupBackup> {
        let backups = self.storage.list_startup_backups()?;
        let b = backups.into_iter().find(|r| r.backup.id == backup_id)
            .ok_or_else(|| AegisError::NotFound(format!("backup {backup_id}")))?;

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Registry::*;
            let root = if b.hive == "user" { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };
            let subkey: Vec<u16> = b.backup.container.encode_utf16().chain(std::iter::once(0)).collect();
            let val_name: Vec<u16> = b.value_name.encode_utf16().chain(std::iter::once(0)).collect();
            let val_data: Vec<u16> = b.backup.value.encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExW(root, subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) == 0 {
                    RegSetValueExW(
                        hkey,
                        val_name.as_ptr(),
                        0,
                        REG_SZ,
                        val_data.as_ptr() as *const _,
                        (val_data.len() * 2) as u32,
                    );
                    RegCloseKey(hkey);
                }
            }
        }

        self.storage.mark_startup_backup_restored(backup_id)?;
        Ok(b.backup)
    }
}
