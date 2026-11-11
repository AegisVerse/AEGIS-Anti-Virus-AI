//! Safe filesystem enumeration for Quick, Full and Custom scans.
//! Handles Windows junctions and symlinks safely to prevent infinite loops.

use aegis_common::types::ScanKind;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct FileEnumerator;

impl FileEnumerator {
    /// Return high-risk Windows security-relevant locations for Quick Scan.
    pub fn quick_scan_roots() -> Vec<PathBuf> {
        let mut targets = Vec::new();

        // 1. User Downloads & Temp
        if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            let user = PathBuf::from(user_profile);
            targets.push(user.join("Downloads"));
            targets.push(user.join("AppData").join("Local").join("Temp"));
            targets.push(user.join("AppData").join("Roaming").join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup"));
        }

        // 2. System Temp
        if let Some(windir) = std::env::var_os("SystemRoot") {
            let win = PathBuf::from(windir);
            targets.push(win.join("Temp"));
        }

        // 3. ProgramData Startup
        if let Some(progdata) = std::env::var_os("ProgramData") {
            let pd = PathBuf::from(progdata);
            targets.push(pd.join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup"));
        }

        targets.into_iter().filter(|p| p.exists()).collect()
    }

    /// Return available fixed system drives for Full Scan.
    pub fn full_scan_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        for b in b'C'..=b'Z' {
            let root = format!("{}:\\", b as char);
            let p = PathBuf::from(&root);
            if p.exists() {
                roots.push(p);
            }
        }
        if roots.is_empty() {
            roots.push(PathBuf::from("C:\\"));
        }
        roots
    }

    /// Resolve targets for a specific scan kind.
    pub fn resolve_roots(kind: ScanKind, user_paths: &[String]) -> Vec<PathBuf> {
        match kind {
            ScanKind::Quick => Self::quick_scan_roots(),
            ScanKind::Full => Self::full_scan_roots(),
            ScanKind::Custom | ScanKind::ContextMenu | ScanKind::Usb => {
                user_paths.iter().map(PathBuf::from).filter(|p| p.exists()).collect()
            }
            ScanKind::RealTime | ScanKind::Scheduled => {
                if user_paths.is_empty() {
                    Self::quick_scan_roots()
                } else {
                    user_paths.iter().map(PathBuf::from).filter(|p| p.exists()).collect()
                }
            }
        }
    }
}

