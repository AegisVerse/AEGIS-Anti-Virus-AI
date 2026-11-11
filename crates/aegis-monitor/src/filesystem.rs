//! Event-driven filesystem monitoring for high-risk user and system locations.

use aegis_behavior::RansomwareShield;
use aegis_common::hash::{sha256_bytes, sha256_file};
use aegis_common::types::*;
use aegis_heuristics::HashReputation;
use aegis_storage::Storage;
use aegis_yara::YaraEngine;
use chrono::Utc;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub struct RealTimeWatcher {
    storage: Arc<Storage>,
    yara: Arc<YaraEngine>,
    hashes: Arc<HashReputation>,
    ransomware: Arc<RansomwareShield>,
    watcher: Option<RecommendedWatcher>,
    enabled: Arc<AtomicBool>,
    paused_until: Arc<RwLock<Option<Timestamp>>>,
    recent_events: Arc<RwLock<HashMap<PathBuf, Instant>>>,
}

impl RealTimeWatcher {
    pub fn new(
        storage: Arc<Storage>,
        yara: Arc<YaraEngine>,
        hashes: Arc<HashReputation>,
        ransomware: Arc<RansomwareShield>,
    ) -> Self {
        Self {
            storage,
            yara,
            hashes,
            ransomware,
            watcher: None,
            enabled: Arc::new(AtomicBool::new(true)),
            paused_until: Arc::new(RwLock::new(None)),
            recent_events: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_enabled(&self, val: bool) {
        self.enabled.store(val, Ordering::SeqCst);
    }

    pub fn set_paused_until(&self, until: Option<Timestamp>) {
        *self.paused_until.write() = until;
    }

    pub fn is_active(&self) -> bool {
        if !self.enabled.load(Ordering::SeqCst) {
            return false;
        }
        if let Some(until) = *self.paused_until.read() {
            if Utc::now() < until {
                return false;
            }
        }
        true
    }

    /// Start watching user high-risk directories (Downloads, Temp, Startup).
    pub fn start(&mut self) -> aegis_common::Result<()> {
        let (tx, rx) = crossbeam_channel::unbounded();

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default(),
        )
        .map_err(|e| aegis_common::AegisError::Internal(format!("failed to initialize watcher: {e}")))?;

        // Collect watch directories
        let mut watch_dirs = Vec::new();
        if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            let base = PathBuf::from(user_profile);
            watch_dirs.push(base.join("Downloads"));
            watch_dirs.push(base.join("Desktop"));
            watch_dirs.push(base.join("AppData").join("Local").join("Temp"));
        }

        for dir in &watch_dirs {
            if dir.exists() {
                let _ = watcher.watch(dir, RecursiveMode::Recursive);
                tracing::info!("Real-time watcher active on: {}", dir.display());
            }
        }

        self.watcher = Some(watcher);

        // Spawn background handler
        let storage = self.storage.clone();
        let yara = self.yara.clone();
        let hashes = self.hashes.clone();
        let ransomware = self.ransomware.clone();
        let enabled = self.enabled.clone();
        let paused_until = self.paused_until.clone();
        let recent = self.recent_events.clone();

        std::thread::Builder::new()
            .name("aegis-fs-monitor".into())
            .spawn(move || {
                Self::process_events(rx, storage, yara, hashes, ransomware, enabled, paused_until, recent);
            })
            .map_err(|e| aegis_common::AegisError::Internal(format!("failed to spawn watcher loop: {e}")))?;

        Ok(())
    }

    fn process_events(
        rx: crossbeam_channel::Receiver<Event>,
        storage: Arc<Storage>,
        yara: Arc<YaraEngine>,
        hashes: Arc<HashReputation>,
        ransomware: Arc<RansomwareShield>,
        enabled: Arc<AtomicBool>,
        paused_until: Arc<RwLock<Option<Timestamp>>>,
        recent: Arc<RwLock<HashMap<PathBuf, Instant>>>,
    ) {
        while let Ok(event) = rx.recv() {
            if !enabled.load(Ordering::SeqCst) {
                continue;
            }
            if let Some(until) = *paused_until.read() {
                if Utc::now() < until {
                    continue;
                }
            }

            let action_str = match event.kind {
                EventKind::Create(_) => "create",
                EventKind::Modify(_) => "modify",
                EventKind::Remove(_) => "delete",
                _ => continue,
            };

            for path in event.paths {
                if !path.is_file() {
                    continue;
                }

                // Debounce duplicate events on the same file within 1 second
                {
                    let mut r = recent.write();
                    if let Some(last_seen) = r.get(&path) {
                        if last_seen.elapsed() < Duration::from_millis(1000) {
                            continue;
                        }
                    }
                    r.insert(path.clone(), Instant::now());

                    // Bound recent map size
                    if r.len() > 10_000 {
                        r.clear();
                    }
                }

                let folder = path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                let file_name = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();

                // 1. Notify ransomware shield
                ransomware.record_file_event(&folder, &file_name, action_str);

                // 2. Perform quick file scan on create/modify
                if action_str == "create" || action_str == "modify" {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        // Skip huge files in real-time
                        if metadata.len() > 32 * 1024 * 1024 {
                            continue;
                        }

                        if let Ok(bytes) = std::fs::read(&path) {
                            let sha256 = sha256_bytes(&bytes);
                            let mut detections = Vec::new();

                            // Hash lookup
                            if let Some(hit) = hashes.lookup(&sha256) {
                                detections.push(hit);
                            }

                            // YARA scan
                            if let Ok(hits) = yara.scan_bytes(&bytes, Duration::from_secs(2)) {
                                detections.extend(hits);
                            }

                            if !detections.is_empty() {
                                let max_sev = detections.iter().map(|d| d.severity).max().unwrap_or(Severity::Medium);
                                let primary_name = detections[0].name.clone();

                                let threat_record = ThreatRecord {
                                    id: Uuid::new_v4().to_string(),
                                    job_id: None,
                                    path: path.to_string_lossy().to_string(),
                                    sha256: Some(sha256),
                                    file_size: Some(metadata.len()),
                                    verdict: if max_sev >= Severity::High { Verdict::Malicious } else { Verdict::Suspicious },
                                    severity: max_sev,
                                    name: primary_name,
                                    detections,
                                    status: ThreatStatus::Active,
                                    detected_at: Utc::now(),
                                    updated_at: Utc::now(),
                                };

                                let _ = storage.insert_threat(&threat_record);
                                let _ = storage.insert_event(&NewEvent::new(
                                    EventCategory::RealTime,
                                    max_sev,
                                    "realtime.threat_intercepted",
                                    format!("Real-Time Detection: {}", threat_record.name),
                                    format!("Path: {}", threat_record.path),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
}

