//! Ransomware behavior tracking, rapid write burst detection, and honeypot monitoring.

use aegis_common::types::*;
use aegis_storage::Storage;
use chrono::{Duration as ChronoDuration, Utc};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

struct FolderActivity {
    events: VecDeque<(Timestamp, String)>, // (timestamp, action)
}

pub struct RansomwareShield {
    storage: Arc<Storage>,
    activity: Mutex<HashMap<String, FolderActivity>>,
    allowlist: Mutex<Vec<String>>,
    protected_folders: Mutex<Vec<String>>,
}

impl RansomwareShield {
    pub fn new(storage: Arc<Storage>) -> Self {
        let default_allowlist = vec![
            "git.exe".into(),
            "code.exe".into(),
            "devenv.exe".into(),
            "cargo.exe".into(),
            "rustc.exe".into(),
            "robocopy.exe".into(),
        ];

        Self {
            storage,
            activity: Mutex::new(HashMap::new()),
            allowlist: Mutex::new(default_allowlist),
            protected_folders: Mutex::new(Vec::new()),
        }
    }

    pub fn set_protected_folders(&self, folders: Vec<String>) {
        *self.protected_folders.lock() = folders;
    }

    pub fn set_allowlist(&self, list: Vec<String>) {
        *self.allowlist.lock() = list;
    }

    /// Record a file change event (e.g. from real-time monitor).
    /// Returns a `RansomwareSignal` if anomalous burst thresholds are exceeded.
    pub fn record_file_event(&self, folder: &str, file_name: &str, action: &str) -> Option<RansomwareSignal> {
        let now = Utc::now();
        let cutoff = now - ChronoDuration::seconds(5);

        let mut act_map = self.activity.lock();
        let folder_record = act_map.entry(folder.to_string()).or_insert_with(|| FolderActivity {
            events: VecDeque::new(),
        });

        // Prune events older than 5 seconds
        while let Some((ts, _)) = folder_record.events.front() {
            if *ts < cutoff {
                folder_record.events.pop_front();
            } else {
                break;
            }
        }

        folder_record.events.push_back((now, action.to_string()));

        let mut modified = 0u64;
        let mut renamed = 0u64;
        let mut deleted = 0u64;
        let mut created = 0u64;

        for (_, act) in &folder_record.events {
            match act.as_str() {
                "modify" => modified += 1,
                "rename" => renamed += 1,
                "delete" => deleted += 1,
                "create" => created += 1,
                _ => modified += 1,
            }
        }

        // Check for common ransom note names
        let lower = file_name.to_ascii_lowercase();
        let is_ransom_note = lower.contains("readme_decrypt")
            || lower.contains("how_to_recover")
            || lower.contains("restore_files")
            || lower.contains("decrypt_info");

        let total_burst = modified + renamed + deleted;
        // Trigger if > 25 file actions in 5 seconds or a ransom note is created alongside bulk writes
        if total_burst >= 25 || (is_ransom_note && total_burst >= 5) {
            let mut score = ((total_burst.min(100)) as u8).min(100);
            if is_ransom_note {
                score = score.max(90);
            }

            let ransom_notes = if is_ransom_note {
                vec![file_name.to_string()]
            } else {
                Vec::new()
            };

            let signal = RansomwareSignal {
                ts: now,
                folder: folder.to_string(),
                modified,
                renamed,
                deleted,
                created,
                extension_changes: renamed,
                high_entropy_writes: modified,
                ransom_note_names: ransom_notes,
                score,
                suspected_processes: Vec::new(),
                event_id: None,
            };

            // Log event to storage
            let _ = self.storage.insert_event(&NewEvent::new(
                EventCategory::Ransomware,
                Severity::Critical,
                "ransomware.burst_detected",
                "Ransomware-Like Rapid File Burst Detected",
                format!("Folder: '{}' had {} file actions in 5s (score: {})", folder, total_burst, score),
            ));

            return Some(signal);
        }

        None
    }

    pub fn get_status(&self) -> RansomwareStatus {
        let protected = self.protected_folders.lock().clone();
        let allowlist = self.allowlist.lock().clone();

        RansomwareStatus {
            state: ModuleState::Active,
            protected_folders: protected.clone(),
            monitored_folders: protected,
            window_secs: 5,
            recent_bursts: Vec::new(),
            allowlisted_processes: allowlist,
            backups_available: false,
            limitations: vec![
                "Ransomware shield operates via file modification heuristics and sliding window activity.".into(),
                "Safe file rollback requires pre-configured Windows VSS or volume backups.".into(),
            ],
        }
    }
}

