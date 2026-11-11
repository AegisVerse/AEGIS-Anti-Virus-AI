//! Static heuristics, PE structure analysis, entropy checks, and local
//! hash reputation database.

use aegis_common::hash::{shannon_entropy, sha256_bytes};
use aegis_common::types::{
    Detection, DetectionSource, ModuleState, ModuleStatus, Severity, SignatureInfo, SignatureStatus,
};
use aegis_common::{AegisError, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub const EMBEDDED_HASHES_JSON: &str = include_str!("../../../rules/heuristics/hashes.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDbEntry {
    pub sha256: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDbFile {
    pub version: String,
    pub source: String,
    pub license: String,
    pub entries: Vec<HashDbEntry>,
}

pub struct HashReputation {
    map: RwLock<HashMap<String, HashDbEntry>>,
    version: RwLock<String>,
    path: Option<PathBuf>,
}

impl HashReputation {
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        let mut entries = HashMap::new();
        let mut version = "2026.11.1".to_string();

        if let Ok(seed) = serde_json::from_str::<HashDbFile>(EMBEDDED_HASHES_JSON) {
            version = seed.version;
            for e in seed.entries {
                entries.insert(e.sha256.to_ascii_lowercase(), e);
            }
        }

        if let Some(p) = &path {
            if p.exists() {
                if let Ok(content) = std::fs::read_to_string(p) {
                    if let Ok(db) = serde_json::from_str::<HashDbFile>(&content) {
                        version = db.version;
                        for e in db.entries {
                            entries.insert(e.sha256.to_ascii_lowercase(), e);
                        }
                    }
                }
            } else {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(p, EMBEDDED_HASHES_JSON);
            }
        }

        Ok(Self {
            map: RwLock::new(entries),
            version: RwLock::new(version),
            path,
        })
    }

    pub fn lookup(&self, sha256: &str) -> Option<Detection> {
        let g = self.map.read();
        let e = g.get(&sha256.to_ascii_lowercase())?;
        let mut meta = BTreeMap::new();
        meta.insert("sha256".into(), e.sha256.clone());
        Some(Detection {
            source: DetectionSource::HashReputation,
            rule_id: format!("hash:{}", e.sha256),
            name: e.name.clone(),
            severity: e.severity,
            confidence: 100,
            description: e.description.clone(),
            metadata: meta,
        })
    }

    pub fn count(&self) -> u64 {
        self.map.read().len() as u64
    }

    pub fn version(&self) -> String {
        self.version.read().clone()
    }
}

/// Structural PE file heuristics (entropy, section flags, suspicious imports).
pub struct PeHeuristics;

impl PeHeuristics {
    pub fn analyze(bytes: &[u8], filename: &str) -> Vec<Detection> {
        let mut hits = Vec::new();
        if bytes.len() < 64 || bytes[0] != b'M' || bytes[1] != b'Z' {
            return hits;
        }

        let pe = match goblin::pe::PE::parse(bytes) {
            Ok(p) => p,
            Err(_) => return hits,
        };

        // 1. High overall entropy combined with executable code
        let overall_entropy = shannon_entropy(bytes);
        let is_packed = overall_entropy > 7.4;

        // 2. Suspicious section properties (e.g. RWX sections)
        for section in &pe.sections {
            let rwx_flags = 0x20000000 /* EXECUTE */ | 0x80000000 /* WRITE */;
            let is_rwx = (section.characteristics & rwx_flags) == rwx_flags;
            if is_rwx {
                let name = String::from_utf8_lossy(&section.name).trim_matches('\0').to_string();
                let mut meta = BTreeMap::new();
                meta.insert("section".into(), name.clone());
                meta.insert("characteristics".into(), format!("0x{:08X}", section.characteristics));
                hits.push(Detection {
                    source: DetectionSource::Heuristic,
                    rule_id: "heuristic:pe.rwx_section".into(),
                    name: "Heuristic.PE.WritableAndExecutableSection".into(),
                    severity: Severity::Medium,
                    confidence: 70,
                    description: format!("Section '{}' is marked both writable and executable", name),
                    metadata: meta,
                });
            }
        }

        // 3. Suspicious import combinations (e.g. process injection)
        let mut has_mem_alloc = false;
        let mut has_mem_write = false;
        let mut has_thread_create = false;

        for imp in &pe.imports {
            let func_name = imp.name.to_ascii_lowercase();
            if func_name.contains("virtualallocex") {
                has_mem_alloc = true;
            }
            if func_name.contains("writeprocessmemory") {
                has_mem_write = true;
            }
            if func_name.contains("createremotethread") || func_name.contains("queueuserapc") {
                has_thread_create = true;
            }
        }

        if has_mem_alloc && has_mem_write && has_thread_create {
            hits.push(Detection {
                source: DetectionSource::Heuristic,
                rule_id: "heuristic:pe.injection_imports".into(),
                name: "Heuristic.PE.ProcessInjectionApiPattern".into(),
                severity: Severity::High,
                confidence: 75,
                description: "Executable imports APIs commonly paired for remote process injection".into(),
                metadata: BTreeMap::new(),
            });
        }

        // 4. Double extension anomaly (e.g. invoice.pdf.exe)
        let lower_name = filename.to_ascii_lowercase();
        if lower_name.ends_with(".exe") || lower_name.ends_with(".scr") || lower_name.ends_with(".pif") {
            let suspicious_pseudo_exts = [".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".jpg.", ".png.", ".txt."];
            for pse in &suspicious_pseudo_exts {
                if lower_name.contains(pse) {
                    let mut meta = BTreeMap::new();
                    meta.insert("filename".into(), filename.to_string());
                    hits.push(Detection {
                        source: DetectionSource::Heuristic,
                        rule_id: "heuristic:file.double_extension".into(),
                        name: "Heuristic.File.DeceptiveDoubleExtension".into(),
                        severity: Severity::High,
                        confidence: 85,
                        description: "File uses a deceptive double extension to masquerade as a document or image".into(),
                        metadata: meta,
                    });
                    break;
                }
            }
        }

        hits
    }
}

/// Query Authenticode digital signature on Windows via WinVerifyTrust.
pub fn verify_file_signature(path: &Path) -> SignatureInfo {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::*;
        use windows_sys::Win32::Security::Cryptography::*;
        use windows_sys::Win32::Security::WinTrust::*;

        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);

        let mut file_data = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: 0 as _,
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut win_trust_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_data as *mut _,
            },
            dwStateAction: WTD_STATEACTION_IGNORE,
            hWVTStateData: 0 as _,
            pwszURLReference: std::ptr::null_mut(),
            dwProvFlags: WTD_SAFER_FLAG,
            dwUIContext: 0,
            pSignatureSettings: std::ptr::null_mut(),
        };

        let mut action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        let status = unsafe {
            WinVerifyTrust(
                0 as _,
                &mut action_id,
                &mut win_trust_data as *mut _ as *mut std::ffi::c_void,
            )
        };

        if status == 0 {
            SignatureInfo {
                status: SignatureStatus::Valid,
                publisher: None, // Verified valid signature
            }
        } else if status == TRUST_E_NOSIGNATURE as i32 {
            SignatureInfo {
                status: SignatureStatus::Unsigned,
                publisher: None,
            }
        } else if status == TRUST_E_EXPLICIT_DISTRUST as i32 {
            SignatureInfo {
                status: SignatureStatus::Untrusted,
                publisher: None,
            }
        } else {
            SignatureInfo {
                status: SignatureStatus::Invalid,
                publisher: None,
            }
        }
    }

    #[cfg(not(windows))]
    {
        SignatureInfo {
            status: SignatureStatus::Unknown,
            publisher: None,
        }
    }
}

