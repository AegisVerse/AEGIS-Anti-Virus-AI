//! Input validation shared by the IPC boundary and privileged modules.

use crate::error::{AegisError, Result};
use std::path::{Component, Path, PathBuf};

/// Maximum accepted path length in UTF-16 units (Windows extended max).
pub const MAX_PATH_CHARS: usize = 32_000;

/// Validate a user supplied filesystem path for scanning/restore targets.
///
/// Requirements: absolute, no NUL, no `..` components, no device namespace
/// (`\\.\`), no alternate-data-stream syntax beyond the drive colon, and
/// bounded length. The path does not need to exist.
pub fn validate_user_path(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() {
        return Err(AegisError::InvalidInput("empty path".into()));
    }
    if raw.encode_utf16().count() > MAX_PATH_CHARS {
        return Err(AegisError::InvalidInput("path too long".into()));
    }
    if raw.contains('\0') {
        return Err(AegisError::InvalidInput("path contains NUL".into()));
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(r"\\.\") || lower.starts_with(r"\\?\globalroot") || lower.starts_with("//./") {
        return Err(AegisError::InvalidInput("device paths are not allowed".into()));
    }
    // Reject ADS / odd colons: the only allowed colon is the drive-letter one
    // (also present once in a `\\?\C:` verbatim prefix).
    if raw.matches(':').count() > 1 {
        return Err(AegisError::InvalidInput("alternate data streams are not allowed".into()));
    }
    let p = PathBuf::from(raw);
    if !p.is_absolute() {
        return Err(AegisError::InvalidInput("path must be absolute".into()));
    }
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(AegisError::InvalidInput("path traversal is not allowed".into()));
    }
    Ok(p)
}

/// Validate an identifier (uuid-like or slug): `[A-Za-z0-9_-]{1,64}`.
pub fn validate_id(id: &str) -> Result<&str> {
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(AegisError::InvalidInput("invalid identifier".into()));
    }
    Ok(id)
}

/// Normalize and validate a DNS domain name (IDNA must already be applied).
pub fn normalize_domain(raw: &str) -> Result<String> {
    let mut d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = d.strip_prefix("*.") {
        d = rest.to_string();
    }
    if d.is_empty() || d.len() > 253 {
        return Err(AegisError::InvalidInput("invalid domain length".into()));
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return Err(AegisError::InvalidInput("domain must contain a dot".into()));
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 {
            return Err(AegisError::InvalidInput("invalid domain label".into()));
        }
        if !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') || l.starts_with('-') || l.ends_with('-') {
            return Err(AegisError::InvalidInput(format!("invalid characters in domain label '{l}'")));
        }
    }
    Ok(d)
}

/// Validate a public/unicast IP address string for firewall blocking.
pub fn validate_block_ip(raw: &str) -> Result<std::net::IpAddr> {
    let ip: std::net::IpAddr = raw
        .trim()
        .parse()
        .map_err(|_| AegisError::InvalidInput("invalid IP address".into()))?;
    let bad = match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_multicast(),
    };
    if bad {
        return Err(AegisError::InvalidInput("refusing to block loopback/unspecified/multicast address".into()));
    }
    Ok(ip)
}

/// Returns true if `child` is inside `parent` (case-insensitive on Windows).
pub fn path_is_within(child: &Path, parent: &Path) -> bool {
    let c = child.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
    let mut p = parent.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
    if !p.ends_with('\\') {
        p.push('\\');
    }
    c.starts_with(&p) || c == p.trim_end_matches('\\')
}

/// Truncate untrusted text for display/logging and strip control chars.
pub fn sanitize_text(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() && c != '\n' && c != '\t' { ' ' } else { c })
        .take(max)
        .collect();
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_paths() {
        assert!(validate_user_path("").is_err());
        assert!(validate_user_path("relative\\x").is_err());
        assert!(validate_user_path(r"C:\a\..\Windows").is_err());
        assert!(validate_user_path(r"\\.\PhysicalDrive0").is_err());
        assert!(validate_user_path(r"C:\file.txt:stream").is_err());
        assert!(validate_user_path("C:\\a\0b").is_err());
    }

    #[test]
    fn accepts_good_paths() {
        assert!(validate_user_path(r"C:\Users\x\Downloads").is_ok());
        assert!(validate_user_path(r"\\?\C:\very\long").is_ok());
        assert!(validate_user_path(r"D:\").is_ok());
    }

    #[test]
    fn long_path_limit() {
        let long = format!("C:\\{}", "a\\".repeat(20_000));
        assert!(validate_user_path(&long).is_err());
        let ok = format!("C:\\{}", "abcdefgh\\".repeat(100));
        assert!(validate_user_path(&ok).is_ok());
    }

    #[test]
    fn domains() {
        assert_eq!(normalize_domain(" Ads.Example.COM. ").unwrap(), "ads.example.com");
        assert_eq!(normalize_domain("*.example.com").unwrap(), "example.com");
        assert!(normalize_domain("localhost").is_err());
        assert!(normalize_domain("a b.com").is_err());
        assert!(normalize_domain("-bad.com").is_err());
        assert!(normalize_domain("x.com; rm -rf").is_err());
    }

    #[test]
    fn ids() {
        assert!(validate_id("abc-123_X").is_ok());
        assert!(validate_id("../etc").is_err());
        assert!(validate_id("").is_err());
    }

    #[test]
    fn ips() {
        assert!(validate_block_ip("8.8.8.8").is_ok());
        assert!(validate_block_ip("127.0.0.1").is_err());
        assert!(validate_block_ip("::1").is_err());
        assert!(validate_block_ip("1.2.3").is_err());
    }

    #[test]
    fn within() {
        assert!(path_is_within(Path::new(r"C:\Windows\System32\x.dll"), Path::new(r"c:\windows")));
        assert!(!path_is_within(Path::new(r"C:\WindowsApps\x"), Path::new(r"C:\Windows")));
    }
}
