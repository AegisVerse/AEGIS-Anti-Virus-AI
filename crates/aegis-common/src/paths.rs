//! Well-known locations. Privileged (service) data lives under
//! `%ProgramData%\AEGIS AI Security`; user-mode engine data lives under
//! `%LOCALAPPDATA%\AEGIS AI Security`. The two never share writable files.

use std::path::{Path, PathBuf};

pub const APP_DIR_NAME: &str = "AEGIS AI Security";
pub const SERVICE_NAME: &str = "AegisAiSecurity";
pub const SERVICE_DISPLAY_NAME: &str = "AEGIS AI Security Service";
/// Named pipe used by the LocalSystem service.
pub const SERVICE_PIPE: &str = r"\\.\pipe\aegis-ai-security.v1";
/// Prefix of the per-user pipe used by the user-mode engine.
pub const USER_PIPE_PREFIX: &str = r"\\.\pipe\aegis-ai-security.user.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineMode {
    /// Windows service running as LocalSystem.
    Service,
    /// Per-user engine running with the user's token (no elevation).
    User,
}

impl EngineMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            EngineMode::Service => "service",
            EngineMode::User => "user",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DataLayout {
    pub root: PathBuf,
    pub db: PathBuf,
    pub quarantine: PathBuf,
    pub rules: PathBuf,
    pub rules_staging: PathBuf,
    pub models: PathBuf,
    pub logs: PathBuf,
    pub backups: PathBuf,
    pub reports: PathBuf,
}

impl DataLayout {
    pub fn under(root: impl AsRef<Path>) -> DataLayout {
        let root = root.as_ref().to_path_buf();
        DataLayout {
            db: root.join("aegis.db"),
            quarantine: root.join("Quarantine"),
            rules: root.join("rules"),
            rules_staging: root.join("rules-staging"),
            models: root.join("models"),
            logs: root.join("logs"),
            backups: root.join("backups"),
            reports: root.join("reports"),
            root,
        }
    }

    pub fn for_mode(mode: EngineMode) -> DataLayout {
        let base = match mode {
            EngineMode::Service => std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")),
            EngineMode::User => std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
        };
        DataLayout::under(base.join(APP_DIR_NAME))
    }

    pub fn create_all(&self) -> std::io::Result<()> {
        for d in [&self.root, &self.quarantine, &self.rules, &self.rules_staging, &self.models, &self.logs, &self.backups, &self.reports] {
            std::fs::create_dir_all(d)?;
        }
        Ok(())
    }
}

/// Pipe name for the per-user engine, derived from a sanitized user name.
pub fn user_pipe_name() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
    let safe: String = user
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .take(40)
        .collect();
    format!("{USER_PIPE_PREFIX}{safe}")
}

/// Common Windows directories that must never be auto-remediated.
pub fn protected_system_roots() -> Vec<PathBuf> {
    let windir = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let mut v = vec![windir];
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Some(p) = std::env::var_os(var) {
            let p = PathBuf::from(p);
            v.push(p.join("Windows Defender"));
            v.push(p.join("Common Files").join("microsoft shared"));
        }
    }
    v
}

pub fn is_protected_system_path(p: &Path) -> bool {
    protected_system_roots().iter().any(|r| crate::validate::path_is_within(p, r))
}
