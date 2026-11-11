//! Core scanning execution pipeline combining YARA-X, heuristics, hash reputation,
//! caching and threat records.

use crate::archive::{extract_bounded_entries, ArchiveLimits};
use crate::enumerator::FileEnumerator;
use aegis_common::hash::{sha256_file, sha256_bytes};
use aegis_common::types::*;
use aegis_common::{AegisError, Result};
use aegis_heuristics::{HashReputation, PeHeuristics};
use aegis_storage::Storage;
use aegis_yara::YaraEngine;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub struct ScannerEngine {
    storage: Arc<Storage>,
    yara: Arc<YaraEngine>,
    hashes: Arc<HashReputation>,
    active_scan: Arc<RwLock<Option<ScanProgress>>>,
    cancel_flag: Arc<AtomicBool>,
    pause_flag: Arc<AtomicBool>,
}

impl ScannerEngine {
    pub fn new(storage: Arc<Storage>, yara: Arc<YaraEngine>, hashes: Arc<HashReputation>) -> Self {
        Self {
            storage,
            yara,
            hashes,
            active_scan: Arc::new(RwLock::new(None)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            pause_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn current_progress(&self) -> Option<ScanProgress> {
        self.active_scan.read().clone()
    }

    pub fn cancel(&self, job_id: &str) -> Result<ScanProgress> {
        let mut g = self.active_scan.write();
        if let Some(prog) = g.as_mut() {
            if prog.job_id == job_id && !prog.state.is_terminal() {
                self.cancel_flag.store(true, Ordering::SeqCst);
                prog.state = ScanState::Cancelling;
                return Ok(prog.clone());
            }
        }
        Err(AegisError::NotFound(format!("running scan job {job_id}")))
    }

    pub fn pause(&self, job_id: &str) -> Result<ScanProgress> {
        let mut g = self.active_scan.write();
        if let Some(prog) = g.as_mut() {
            if prog.job_id == job_id && prog.state == ScanState::Running {
                self.pause_flag.store(true, Ordering::SeqCst);
                prog.state = ScanState::Paused;
                return Ok(prog.clone());
            }
        }
        Err(AegisError::NotFound(format!("running scan job {job_id}")))
    }

    pub fn resume(&self, job_id: &str) -> Result<ScanProgress> {
        let mut g = self.active_scan.write();
        if let Some(prog) = g.as_mut() {
            if prog.job_id == job_id && prog.state == ScanState::Paused {
                self.pause_flag.store(false, Ordering::SeqCst);
                prog.state = ScanState::Running;
                return Ok(prog.clone());
            }
        }
        Err(AegisError::NotFound(format!("paused scan job {job_id}")))
    }

    /// Launch a new scan in a dedicated background worker thread.
    pub fn start_scan(&self, kind: ScanKind, paths: Vec<String>) -> Result<ScanProgress> {
        {
            let g = self.active_scan.read();
            if let Some(p) = g.as_ref() {
                if !p.state.is_terminal() {
                    return Err(AegisError::Busy("another scan is currently in progress".into()));
                }
            }
        }

        let job_id = Uuid::new_v4().to_string();
        let targets = paths.clone();
        let progress = ScanProgress {
            job_id: job_id.clone(),
            kind,
            state: ScanState::Running,
            targets: targets.clone(),
            current_target: None,
            counters: ScanCounters::default(),
            files_discovered: 0,
            enumeration_complete: false,
            started_at: Utc::now(),
            finished_at: None,
            elapsed_ms: 0,
            error: None,
            recent_issues: Vec::new(),
        };

        *self.active_scan.write() = Some(progress.clone());
        self.cancel_flag.store(false, Ordering::SeqCst);
        self.pause_flag.store(false, Ordering::SeqCst);

        let storage = self.storage.clone();
        let yara = self.yara.clone();
        let hashes = self.hashes.clone();
        let active = self.active_scan.clone();
        let cancel = self.cancel_flag.clone();
        let pause = self.pause_flag.clone();

        std::thread::Builder::new()
            .name("aegis-scanner-worker".into())
            .spawn(move || {
                Self::run_scan_worker(job_id, kind, targets, storage, yara, hashes, active, cancel, pause);
            })
            .map_err(|e| AegisError::Internal(format!("failed to spawn scanner thread: {e}")))?;

        Ok(progress)
    }

    fn run_scan_worker(
        job_id: String,
        kind: ScanKind,
        target_strings: Vec<String>,
        storage: Arc<Storage>,
        yara: Arc<YaraEngine>,
        hashes: Arc<HashReputation>,
        active: Arc<RwLock<Option<ScanProgress>>>,
        cancel: Arc<AtomicBool>,
        pause: Arc<AtomicBool>,
    ) {
        let roots = FileEnumerator::resolve_roots(kind, &target_strings);
        let start_time = Instant::now();

        // 1. Enumerate files with breadth-first search, honoring symlinks safely
        let mut file_queue: Vec<PathBuf> = Vec::new();
        let mut dir_queue: Vec<PathBuf> = roots.clone();
        let mut visited_dirs = HashSet::new();

        while let Some(dir) = dir_queue.pop() {
            if cancel.load(Ordering::SeqCst) {
                break;
            }

            // Canonicalize to prevent symlink cycles
            if let Ok(canon) = dir.canonicalize() {
                if !visited_dirs.insert(canon) {
                    continue;
                }
            }

            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_dir() {
                            // Don't recurse into deep virtual Windows dirs during full scan
                            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                            if name != "$recycle.bin" && name != "system volume information" {
                                dir_queue.push(path);
                            }
                        } else if ft.is_file() {
                            file_queue.push(path);
                        }
                    }
                }
            }

            // Update discovered count periodically
            if let Some(prog) = active.write().as_mut() {
                prog.files_discovered = file_queue.len() as u64;
            }
        }

        if let Some(prog) = active.write().as_mut() {
            prog.files_discovered = file_queue.len() as u64;
            prog.enumeration_complete = true;
        }

        // 2. Scan files in file_queue
        let archive_limits = ArchiveLimits::default();

        for file_path in file_queue {
            if cancel.load(Ordering::SeqCst) {
                break;
            }

            while pause.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
                if cancel.load(Ordering::SeqCst) {
                    break;
                }
            }

            let path_str = file_path.to_string_lossy().to_string();

            // Update current target in progress
            if let Some(prog) = active.write().as_mut() {
                prog.current_target = Some(path_str.clone());
                prog.elapsed_ms = start_time.elapsed().as_millis() as u64;
            }

            let metadata = match std::fs::metadata(&file_path) {
                Ok(m) => m,
                Err(err) => {
                    if let Some(prog) = active.write().as_mut() {
                        prog.counters.skipped += 1;
                        if prog.recent_issues.len() < 50 {
                            prog.recent_issues.push(ScanIssue {
                                path: path_str,
                                reason: format!("metadata error: {err}"),
                            });
                        }
                    }
                    continue;
                }
            };

            let file_size = metadata.len();
            // Skip files larger than 128MB for regular memory scans
            if file_size > 128 * 1024 * 1024 {
                if let Some(prog) = active.write().as_mut() {
                    prog.counters.skipped += 1;
                    if prog.recent_issues.len() < 50 {
                        prog.recent_issues.push(ScanIssue {
                            path: path_str,
                            reason: "exceeds maximum file size limit (128 MB)".into(),
                        });
                    }
                }
                continue;
            }

            // Read file content
            let file_bytes = match std::fs::read(&file_path) {
                Ok(b) => b,
                Err(err) => {
                    if let Some(prog) = active.write().as_mut() {
                        prog.counters.errors += 1;
                        if prog.recent_issues.len() < 50 {
                            prog.recent_issues.push(ScanIssue {
                                path: path_str,
                                reason: format!("read error: {err}"),
                            });
                        }
                    }
                    continue;
                }
            };

            let sha256 = sha256_bytes(&file_bytes);
            let mut file_detections = Vec::new();

            // Check A: Hash Reputation
            if let Some(hit) = hashes.lookup(&sha256) {
                file_detections.push(hit);
            }

            // Check B: YARA-X rules
            if let Ok(hits) = yara.scan_bytes(&file_bytes, Duration::from_secs(3)) {
                file_detections.extend(hits);
            }

            // Check C: PE Heuristics
            let pe_hits = PeHeuristics::analyze(&file_bytes, &file_path.file_name().unwrap_or_default().to_string_lossy());
            file_detections.extend(pe_hits);

            // Check D: If archive (.zip), inspect bounded entries
            let is_zip = path_str.to_ascii_lowercase().ends_with(".zip");
            if is_zip {
                if let Ok(entries) = extract_bounded_entries(&file_path, &archive_limits) {
                    if let Some(prog) = active.write().as_mut() {
                        prog.counters.archives_scanned += 1;
                    }
                    for entry in entries {
                        if let Ok(hits) = yara.scan_bytes(&entry.data, Duration::from_secs(3)) {
                            for mut hit in hits {
                                hit.description = format!("Inside zip [{}]: {}", entry.name, hit.description);
                                file_detections.push(hit);
                            }
                        }
                    }
                }
            }

            // Evaluate detections
            let has_threat = !file_detections.is_empty();
            if has_threat {
                // Determine verdict and highest severity
                let max_sev = file_detections.iter().map(|d| d.severity).max().unwrap_or(Severity::Medium);
                let primary_name = file_detections[0].name.clone();

                let threat_record = ThreatRecord {
                    id: Uuid::new_v4().to_string(),
                    job_id: Some(job_id.clone()),
                    path: path_str.clone(),
                    sha256: Some(sha256),
                    file_size: Some(file_size),
                    verdict: if max_sev >= Severity::High { Verdict::Malicious } else { Verdict::Suspicious },
                    severity: max_sev,
                    name: primary_name,
                    detections: file_detections,
                    status: ThreatStatus::Active,
                    detected_at: Utc::now(),
                    updated_at: Utc::now(),
                };

                let _ = storage.insert_threat(&threat_record);

                // Insert event into threat_events
                let _ = storage.insert_event(&NewEvent::new(
                    EventCategory::Threat,
                    max_sev,
                    "threat.detected",
                    format!("Threat Detected: {}", threat_record.name),
                    format!("File: {}", threat_record.path),
                ));

                if let Some(prog) = active.write().as_mut() {
                    if max_sev >= Severity::High {
                        prog.counters.threats_found += 1;
                    } else {
                        prog.counters.suspicious_found += 1;
                    }
                }
            }

            if let Some(prog) = active.write().as_mut() {
                prog.counters.files_scanned += 1;
                prog.counters.bytes_scanned += file_size;
            }
        }

        // Finalize state
        let final_state = if cancel.load(Ordering::SeqCst) {
            ScanState::Cancelled
        } else {
            ScanState::Completed
        };

        let now = Utc::now();
        let mut final_summary = None;

        if let Some(prog) = active.write().as_mut() {
            prog.state = final_state;
            prog.finished_at = Some(now);
            prog.elapsed_ms = start_time.elapsed().as_millis() as u64;
            prog.current_target = None;

            final_summary = Some(ScanJobSummary {
                job_id: prog.job_id.clone(),
                kind: prog.kind,
                state: prog.state,
                targets: prog.targets.clone(),
                counters: prog.counters.clone(),
                started_at: prog.started_at,
                finished_at: Some(now),
                error: None,
            });
        }

        if let Some(summary) = final_summary {
            let _ = storage.upsert_scan_job(&summary);
            let _ = storage.insert_event(&NewEvent::new(
                EventCategory::Scan,
                Severity::Info,
                "scan.completed",
                format!("{:?} Scan {}", summary.kind, if summary.state == ScanState::Completed { "Finished" } else { "Cancelled" }),
                format!("Scanned {} files. Threats: {}, Suspicious: {}", summary.counters.files_scanned, summary.counters.threats_found, summary.counters.suspicious_found),
            ));
        }
    }
}

