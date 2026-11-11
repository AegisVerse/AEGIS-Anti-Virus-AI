//! Safe archive inspection with strict resource bounds against zip bombs.

use aegis_common::error::{AegisError, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

pub struct ArchiveLimits {
    pub max_depth: u32,
    pub max_expanded_bytes: u64,
    pub max_file_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_expanded_bytes: 256 * 1024 * 1024, // 256 MB
            max_file_bytes: 64 * 1024 * 1024,      // 64 MB
        }
    }
}

pub struct ArchiveEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Safely inspect a ZIP archive without writing to disk, enforcing max total
/// expanded size and per-file size limits.
pub fn extract_bounded_entries(path: &Path, limits: &ArchiveLimits) -> Result<Vec<ArchiveEntry>> {
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file).map_err(|e| AegisError::Parse(format!("zip error: {e}")))?;

    let mut entries = Vec::new();
    let mut total_bytes = 0u64;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i).map_err(|e| AegisError::Parse(format!("zip entry: {e}")))?;
        if file.is_dir() {
            continue;
        }

        let declared_size = file.size();
        if declared_size > limits.max_file_bytes {
            tracing::warn!("Skipping archive entry {}: exceeds max file size", file.name());
            continue;
        }

        if total_bytes.saturating_add(declared_size) > limits.max_expanded_bytes {
            tracing::warn!("Archive {} exceeds total expanded size limit (potential zip bomb)", path.display());
            break;
        }

        let mut buf = Vec::with_capacity(declared_size.min(1024 * 1024) as usize);
        let mut limited = (&mut file).take(limits.max_file_bytes + 1);
        limited.read_to_end(&mut buf)?;

        if buf.len() as u64 > limits.max_file_bytes {
            tracing::warn!("Entry {} expanded beyond declared size limit", file.name());
            continue;
        }

        total_bytes += buf.len() as u64;
        entries.push(ArchiveEntry {
            name: file.name().to_string(),
            data: buf,
        });

        if total_bytes >= limits.max_expanded_bytes {
            break;
        }
    }

    Ok(entries)
}

