//! SQLite persistence for AEGIS AI Security.
//!
//! A single connection guarded by a mutex is used; SQLite in WAL mode handles
//! the modest write rate of the service comfortably. All queries use bound
//! parameters (no string interpolation of untrusted data).

use aegis_common::types::*;
use aegis_common::{AegisError, Result};
use chrono::{Duration, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MIGRATIONS: &[(i32, &str)] = &[(1, include_str!("migrations/0001_init.sql"))];
const SETTINGS_KEY: &str = "settings";
const MAX_CACHE_ROWS: i64 = 500_000;

fn db_err(e: rusqlite::Error) -> AegisError {
    AegisError::Database(e.to_string())
}

fn ts(t: &Timestamp) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn parse_ts(s: &str) -> Timestamp {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn sev_rank(s: Severity) -> i64 {
    s as i64
}

/// Outcome of opening the database (used for diagnostics / events).
#[derive(Debug, Clone)]
pub struct OpenReport {
    pub recovered_from_corruption: bool,
    pub corrupt_backup: Option<PathBuf>,
}

pub struct Storage {
    conn: Mutex<Connection>,
    path: PathBuf,
}

/// Bundled data stored for a quarantine item that is never exposed over IPC.
#[derive(Debug, Clone)]
pub struct QuarantineSecret {
    pub xor_key: String,
    pub vault_file: String,
}

#[derive(Debug, Clone)]
pub struct StartupBackupRow {
    pub backup: StartupBackup,
    pub item_id: String,
    pub hive: String,
    pub value_name: String,
    pub value_type: u32,
}

impl Storage {
    /// Open (or create) the database. A corrupt database is moved aside to
    /// `<name>.corrupt-<timestamp>` and a fresh one is created so protection
    /// keeps working; the caller should raise an event from the report.
    pub fn open(path: &Path) -> Result<(Storage, OpenReport)> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match Self::try_open(path) {
            Ok(s) => Ok((s, OpenReport { recovered_from_corruption: false, corrupt_backup: None })),
            Err(e) => {
                tracing::error!("database open failed ({e}); attempting recovery");
                let backup = path.with_extension(format!("db.corrupt-{}", Utc::now().format("%Y%m%d%H%M%S")));
                if path.exists() {
                    std::fs::rename(path, &backup)?;
                    for ext in ["db-wal", "db-shm"] {
                        let side = path.with_extension(ext);
                        if side.exists() {
                            let _ = std::fs::remove_file(side);
                        }
                    }
                }
                let s = Self::try_open(path)?;
                Ok((s, OpenReport { recovered_from_corruption: true, corrupt_backup: Some(backup) }))
            }
        }
    }

    pub fn open_in_memory() -> Result<Storage> {
        let conn = Connection::open_in_memory().map_err(db_err)?;
        let s = Storage { conn: Mutex::new(conn), path: PathBuf::from(":memory:") };
        s.migrate()?;
        Ok(s)
    }

    fn try_open(path: &Path) -> Result<Storage> {
        let conn = Connection::open(path).map_err(db_err)?;
        conn.busy_timeout(std::time::Duration::from_secs(5)).map_err(db_err)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(db_err)?;
        conn.pragma_update(None, "synchronous", "NORMAL").map_err(db_err)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(db_err)?;
        let check: String = conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(db_err)?;
        if check != "ok" {
            return Err(AegisError::Database(format!("integrity check failed: {check}")));
        }
        let s = Storage { conn: Mutex::new(conn), path: path.to_path_buf() };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&self) -> Result<()> {
        let mut conn = self.conn.lock();
        let current: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(db_err)?;
        for (version, sql) in MIGRATIONS {
            if *version > current {
                let tx = conn.transaction().map_err(db_err)?;
                tx.execute_batch(sql).map_err(db_err)?;
                tx.pragma_update(None, "user_version", version).map_err(db_err)?;
                tx.commit().map_err(db_err)?;
                tracing::info!("database migrated to schema v{version}");
            }
        }
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i32> {
        self.conn.lock().query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(db_err)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn integrity_ok(&self) -> bool {
        self.conn
            .lock()
            .query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))
            .map(|s| s == "ok")
            .unwrap_or(false)
    }

    pub fn size_bytes(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    // ------------------------------------------------------------ settings

    pub fn load_settings(&self) -> Result<Settings> {
        let conn = self.conn.lock();
        let v: Option<String> = conn
            .query_row("SELECT value FROM app_settings WHERE key = ?1", [SETTINGS_KEY], |r| r.get(0))
            .optional()
            .map_err(db_err)?;
        Ok(match v {
            Some(json) => serde_json::from_str(&json).unwrap_or_else(|e| {
                tracing::warn!("settings unreadable ({e}); using defaults");
                Settings::default()
            }),
            None => Settings::default(),
        })
    }

    pub fn save_settings(&self, s: &Settings) -> Result<()> {
        let json = serde_json::to_string(s)?;
        self.conn
            .lock()
            .execute(
                "INSERT INTO app_settings(key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![SETTINGS_KEY, json, ts(&Utc::now())],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn get_kv(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .lock()
            .query_row("SELECT value FROM app_settings WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(db_err)
    }

    pub fn set_kv(&self, key: &str, value: &str) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO app_settings(key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![key, value, ts(&Utc::now())],
            )
            .map_err(db_err)?;
        Ok(())
    }

    // ------------------------------------------------------------ events

    pub fn insert_event(&self, e: &NewEvent) -> Result<SecurityEvent> {
        let now = Utc::now();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO threat_events(ts, category, severity, severity_rank, kind, title, message, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ts(&now),
                e.category.as_str(),
                e.severity.as_str(),
                sev_rank(e.severity),
                e.kind,
                e.title,
                e.message,
                serde_json::to_string(&e.data)?
            ],
        )
        .map_err(db_err)?;
        Ok(SecurityEvent {
            id: conn.last_insert_rowid(),
            ts: now,
            category: e.category,
            severity: e.severity,
            kind: e.kind.clone(),
            title: e.title.clone(),
            message: e.message.clone(),
            data: e.data.clone(),
        })
    }

    fn row_event(r: &Row) -> rusqlite::Result<SecurityEvent> {
        let cat: String = r.get(2)?;
        let sev: String = r.get(3)?;
        let data: String = r.get(7)?;
        Ok(SecurityEvent {
            id: r.get(0)?,
            ts: parse_ts(&r.get::<_, String>(1)?),
            category: EventCategory::parse(&cat).unwrap_or(EventCategory::System),
            severity: Severity::parse(&sev).unwrap_or(Severity::Info),
            kind: r.get(4)?,
            title: r.get(5)?,
            message: r.get(6)?,
            data: serde_json::from_str(&data).unwrap_or(serde_json::Value::Null),
        })
    }

    pub fn list_events(
        &self,
        category: Option<EventCategory>,
        min_severity: Option<Severity>,
        before_id: Option<i64>,
        limit: u32,
    ) -> Result<Vec<SecurityEvent>> {
        let limit = limit.clamp(1, 1000) as i64;
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, category, severity, severity_rank, kind, title, message, data
                 FROM threat_events
                 WHERE (?1 IS NULL OR category = ?1)
                   AND (?2 IS NULL OR severity_rank >= ?2)
                   AND (?3 IS NULL OR id < ?3)
                 ORDER BY id DESC LIMIT ?4",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(
                params![category.map(|c| c.as_str()), min_severity.map(sev_rank), before_id, limit],
                |r| {
                    // column 4 is severity_rank; shift mapping accordingly
                    let cat: String = r.get(2)?;
                    let sev: String = r.get(3)?;
                    let data: String = r.get(8)?;
                    Ok(SecurityEvent {
                        id: r.get(0)?,
                        ts: parse_ts(&r.get::<_, String>(1)?),
                        category: EventCategory::parse(&cat).unwrap_or(EventCategory::System),
                        severity: Severity::parse(&sev).unwrap_or(Severity::Info),
                        kind: r.get(5)?,
                        title: r.get(6)?,
                        message: r.get(7)?,
                        data: serde_json::from_str(&data).unwrap_or(serde_json::Value::Null),
                    })
                },
            )
            .map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    pub fn get_event(&self, id: i64) -> Result<Option<SecurityEvent>> {
        self.conn
            .lock()
            .query_row(
                "SELECT id, ts, category, severity, severity_rank, kind, title, message, data FROM threat_events WHERE id = ?1",
                [id],
                |r| {
                    let cat: String = r.get(2)?;
                    let sev: String = r.get(3)?;
                    let data: String = r.get(8)?;
                    Ok(SecurityEvent {
                        id: r.get(0)?,
                        ts: parse_ts(&r.get::<_, String>(1)?),
                        category: EventCategory::parse(&cat).unwrap_or(EventCategory::System),
                        severity: Severity::parse(&sev).unwrap_or(Severity::Info),
                        kind: r.get(5)?,
                        title: r.get(6)?,
                        message: r.get(7)?,
                        data: serde_json::from_str(&data).unwrap_or(serde_json::Value::Null),
                    })
                },
            )
            .optional()
            .map_err(db_err)
    }

    /// Events since `since` (oldest first), bounded.
    pub fn events_since(&self, since: Timestamp, limit: u32) -> Result<Vec<SecurityEvent>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, category, severity, kind, title, message, data FROM threat_events
                 WHERE ts >= ?1 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![ts(&since), limit.clamp(1, 5000) as i64], Self::row_event)
            .map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    pub fn purge_events_older_than(&self, days: u32) -> Result<u64> {
        let cutoff = Utc::now() - Duration::days(days as i64);
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM threat_events WHERE ts < ?1", [ts(&cutoff)])
            .map_err(db_err)?;
        let n2 = conn
            .execute("DELETE FROM scan_jobs WHERE started_at < ?1 AND state IN ('completed','cancelled','failed')", [ts(&cutoff)])
            .map_err(db_err)?;
        let n3 = conn
            .execute("DELETE FROM audit_logs WHERE ts < ?1", [ts(&(Utc::now() - Duration::days((days as i64).max(365))))])
            .map_err(db_err)?;
        Ok((n + n2 + n3) as u64)
    }

    pub fn history_stats(&self, days: u32) -> Result<HistoryStats> {
        let days = days.clamp(1, 365);
        let since = Utc::now() - Duration::days(days as i64 - 1);
        let since_day = since.format("%Y-%m-%d").to_string();
        let conn = self.conn.lock();
        let mut map: BTreeMap<String, DayStat> = BTreeMap::new();
        for i in 0..days {
            let d = (since + Duration::days(i as i64)).format("%Y-%m-%d").to_string();
            map.insert(d.clone(), DayStat { day: d, events: 0, threats: 0, scans: 0 });
        }
        let mut q = |sql: &str, f: &mut dyn FnMut(&mut DayStat, u64)| -> Result<()> {
            let mut stmt = conn.prepare(sql).map_err(db_err)?;
            let rows = stmt
                .query_map([&since_day], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .map_err(db_err)?;
            for row in rows {
                let (d, n) = row.map_err(db_err)?;
                if let Some(s) = map.get_mut(&d) {
                    f(s, n as u64);
                }
            }
            Ok(())
        };
        q("SELECT substr(ts,1,10) d, COUNT(*) FROM threat_events WHERE substr(ts,1,10) >= ?1 GROUP BY d", &mut |s, n| s.events = n)?;
        q("SELECT substr(detected_at,1,10) d, COUNT(*) FROM scan_results WHERE substr(detected_at,1,10) >= ?1 GROUP BY d", &mut |s, n| s.threats = n)?;
        q("SELECT substr(started_at,1,10) d, COUNT(*) FROM scan_jobs WHERE substr(started_at,1,10) >= ?1 GROUP BY d", &mut |s, n| s.scans = n)?;
        let mut by_category = BTreeMap::new();
        let mut by_severity = BTreeMap::new();
        {
            let mut stmt = conn
                .prepare("SELECT category, COUNT(*) FROM threat_events WHERE substr(ts,1,10) >= ?1 GROUP BY category")
                .map_err(db_err)?;
            for row in stmt.query_map([&since_day], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(db_err)? {
                let (k, n) = row.map_err(db_err)?;
                by_category.insert(k, n as u64);
            }
            let mut stmt = conn
                .prepare("SELECT severity, COUNT(*) FROM threat_events WHERE substr(ts,1,10) >= ?1 GROUP BY severity")
                .map_err(db_err)?;
            for row in stmt.query_map([&since_day], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(db_err)? {
                let (k, n) = row.map_err(db_err)?;
                by_severity.insert(k, n as u64);
            }
        }
        Ok(HistoryStats { days: map.into_values().collect(), by_category, by_severity })
    }

    // ------------------------------------------------------------ scan jobs

    pub fn upsert_scan_job(&self, j: &ScanJobSummary) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO scan_jobs(job_id, kind, state, targets, counters, started_at, finished_at, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(job_id) DO UPDATE SET state=excluded.state, counters=excluded.counters,
                    finished_at=excluded.finished_at, error=excluded.error",
                params![
                    j.job_id,
                    j.kind.as_str(),
                    j.state.as_str(),
                    serde_json::to_string(&j.targets)?,
                    serde_json::to_string(&j.counters)?,
                    ts(&j.started_at),
                    j.finished_at.as_ref().map(ts),
                    j.error
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    fn row_job(r: &Row) -> rusqlite::Result<ScanJobSummary> {
        let kind: String = r.get(1)?;
        let state: String = r.get(2)?;
        let targets: String = r.get(3)?;
        let counters: String = r.get(4)?;
        Ok(ScanJobSummary {
            job_id: r.get(0)?,
            kind: ScanKind::parse(&kind).unwrap_or(ScanKind::Custom),
            state: ScanState::parse(&state).unwrap_or(ScanState::Failed),
            targets: serde_json::from_str(&targets).unwrap_or_default(),
            counters: serde_json::from_str(&counters).unwrap_or_default(),
            started_at: parse_ts(&r.get::<_, String>(5)?),
            finished_at: r.get::<_, Option<String>>(6)?.map(|s| parse_ts(&s)),
            error: r.get(7)?,
        })
    }

    pub fn list_scan_jobs(&self, limit: u32) -> Result<Vec<ScanJobSummary>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT job_id, kind, state, targets, counters, started_at, finished_at, error FROM scan_jobs ORDER BY started_at DESC LIMIT ?1")
            .map_err(db_err)?;
        let rows = stmt.query_map([limit.clamp(1, 500) as i64], Self::row_job).map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    pub fn last_finished_scan(&self, kinds: &[ScanKind]) -> Result<Option<ScanJobSummary>> {
        let jobs = self.list_scan_jobs(200)?;
        Ok(jobs
            .into_iter()
            .find(|j| j.state == ScanState::Completed && (kinds.is_empty() || kinds.contains(&j.kind))))
    }

    /// Mark jobs left `running` by a crash as failed.
    pub fn fail_interrupted_jobs(&self) -> Result<u64> {
        let n = self
            .conn
            .lock()
            .execute(
                "UPDATE scan_jobs SET state='failed', error='interrupted (service stopped or crashed)', finished_at=?1
                 WHERE state IN ('queued','running','paused','cancelling')",
                [ts(&Utc::now())],
            )
            .map_err(db_err)?;
        Ok(n as u64)
    }

    // ------------------------------------------------------------ threats

    pub fn insert_threat(&self, t: &ThreatRecord) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO scan_results(threat_id, job_id, path, sha256, file_size, verdict, severity, name, detections, status, detected_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    t.id,
                    t.job_id,
                    t.path,
                    t.sha256,
                    t.file_size.map(|v| v as i64),
                    serde_json::to_value(t.verdict)?.as_str().unwrap_or("suspicious"),
                    t.severity.as_str(),
                    t.name,
                    serde_json::to_string(&t.detections)?,
                    t.status.as_str(),
                    ts(&t.detected_at),
                    ts(&t.updated_at)
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    fn row_threat(r: &Row) -> rusqlite::Result<ThreatRecord> {
        let verdict: String = r.get(5)?;
        let sev: String = r.get(6)?;
        let det: String = r.get(8)?;
        let status: String = r.get(9)?;
        Ok(ThreatRecord {
            id: r.get(0)?,
            job_id: r.get(1)?,
            path: r.get(2)?,
            sha256: r.get(3)?,
            file_size: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
            verdict: serde_json::from_value(serde_json::Value::String(verdict)).unwrap_or(Verdict::Suspicious),
            severity: Severity::parse(&sev).unwrap_or(Severity::Medium),
            name: r.get(7)?,
            detections: serde_json::from_str(&det).unwrap_or_default(),
            status: ThreatStatus::parse(&status).unwrap_or(ThreatStatus::Active),
            detected_at: parse_ts(&r.get::<_, String>(10)?),
            updated_at: parse_ts(&r.get::<_, String>(11)?),
        })
    }

    const THREAT_COLS: &'static str =
        "threat_id, job_id, path, sha256, file_size, verdict, severity, name, detections, status, detected_at, updated_at";

    pub fn get_threat(&self, id: &str) -> Result<Option<ThreatRecord>> {
        let sql = format!("SELECT {} FROM scan_results WHERE threat_id = ?1", Self::THREAT_COLS);
        self.conn.lock().query_row(&sql, [id], Self::row_threat).optional().map_err(db_err)
    }

    pub fn list_threats(&self, status: Option<ThreatStatus>, limit: u32) -> Result<Vec<ThreatRecord>> {
        let sql = format!(
            "SELECT {} FROM scan_results WHERE (?1 IS NULL OR status = ?1) ORDER BY detected_at DESC LIMIT ?2",
            Self::THREAT_COLS
        );
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(params![status.map(|s| s.as_str()), limit.clamp(1, 1000) as i64], Self::row_threat)
            .map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    /// Find an existing active threat for the same path + hash (dedup).
    pub fn find_active_threat(&self, path: &str, sha256: Option<&str>) -> Result<Option<ThreatRecord>> {
        let sql = format!(
            "SELECT {} FROM scan_results WHERE path = ?1 AND (sha256 IS ?2) AND status = 'active' LIMIT 1",
            Self::THREAT_COLS
        );
        self.conn.lock().query_row(&sql, params![path, sha256], Self::row_threat).optional().map_err(db_err)
    }

    /// True if the user allowed this hash (false-positive override).
    pub fn is_hash_allowed(&self, sha256: &str) -> Result<bool> {
        let n: i64 = self
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM scan_results WHERE sha256 = ?1 AND status = 'allowed'", [sha256], |r| r.get(0))
            .map_err(db_err)?;
        Ok(n > 0)
    }

    pub fn set_threat_status(&self, id: &str, status: ThreatStatus) -> Result<()> {
        let n = self
            .conn
            .lock()
            .execute(
                "UPDATE scan_results SET status = ?1, updated_at = ?2 WHERE threat_id = ?3",
                params![status.as_str(), ts(&Utc::now()), id],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Err(AegisError::NotFound(format!("threat {id}")));
        }
        Ok(())
    }

    pub fn count_threats(&self, status: Option<ThreatStatus>) -> Result<u64> {
        let n: i64 = self
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM scan_results WHERE (?1 IS NULL OR status = ?1)", [status.map(|s| s.as_str())], |r| r.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }

    // ------------------------------------------------------------ rule stats

    pub fn record_rule_hit(&self, rule_id: &str, source: &str) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO detection_rules(rule_id, source, hits, last_hit) VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT(rule_id) DO UPDATE SET hits = hits + 1, last_hit = excluded.last_hit",
                params![rule_id, source, ts(&Utc::now())],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn record_false_positive(&self, rule_id: &str, source: &str) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO detection_rules(rule_id, source, hits, false_positives) VALUES (?1, ?2, 0, 1)
                 ON CONFLICT(rule_id) DO UPDATE SET false_positives = false_positives + 1",
                params![rule_id, source],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn rule_stats(&self) -> Result<BTreeMap<String, (u64, u64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT rule_id, hits, false_positives FROM detection_rules").map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64)))
            .map_err(db_err)?;
        let mut m = BTreeMap::new();
        for row in rows {
            let (k, h, f) = row.map_err(db_err)?;
            m.insert(k, (h, f));
        }
        Ok(m)
    }

    // ------------------------------------------------------------ quarantine

    pub fn insert_quarantine(&self, q: &QuarantineItem, secret: &QuarantineSecret) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO quarantine_items(id, threat_id, original_path, sha256, size, threat_name, severity, state, xor_key, vault_file, quarantined_at, updated_at, note)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    q.id,
                    q.threat_id,
                    q.original_path,
                    q.sha256,
                    q.size as i64,
                    q.threat_name,
                    q.severity.as_str(),
                    q.state.as_str(),
                    secret.xor_key,
                    secret.vault_file,
                    ts(&q.quarantined_at),
                    ts(&q.updated_at),
                    q.note
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    fn row_quarantine(r: &Row) -> rusqlite::Result<(QuarantineItem, QuarantineSecret)> {
        let sev: String = r.get(6)?;
        let state: String = r.get(7)?;
        Ok((
            QuarantineItem {
                id: r.get(0)?,
                threat_id: r.get(1)?,
                original_path: r.get(2)?,
                sha256: r.get(3)?,
                size: r.get::<_, i64>(4)? as u64,
                threat_name: r.get(5)?,
                severity: Severity::parse(&sev).unwrap_or(Severity::Medium),
                state: QuarantineState::parse(&state).unwrap_or(QuarantineState::Failed),
                quarantined_at: parse_ts(&r.get::<_, String>(10)?),
                updated_at: parse_ts(&r.get::<_, String>(11)?),
                note: r.get(12)?,
            },
            QuarantineSecret { xor_key: r.get(8)?, vault_file: r.get(9)? },
        ))
    }

    const Q_COLS: &'static str = "id, threat_id, original_path, sha256, size, threat_name, severity, state, xor_key, vault_file, quarantined_at, updated_at, note";

    pub fn get_quarantine(&self, id: &str) -> Result<Option<(QuarantineItem, QuarantineSecret)>> {
        let sql = format!("SELECT {} FROM quarantine_items WHERE id = ?1", Self::Q_COLS);
        self.conn.lock().query_row(&sql, [id], Self::row_quarantine).optional().map_err(db_err)
    }

    pub fn list_quarantine(&self, states: &[QuarantineState]) -> Result<Vec<(QuarantineItem, QuarantineSecret)>> {
        let sql = format!("SELECT {} FROM quarantine_items ORDER BY quarantined_at DESC", Self::Q_COLS);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt.query_map([], Self::row_quarantine).map_err(db_err)?;
        let all = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)?;
        Ok(all.into_iter().filter(|(q, _)| states.is_empty() || states.contains(&q.state)).collect())
    }

    pub fn set_quarantine_state(&self, id: &str, state: QuarantineState, note: Option<&str>) -> Result<()> {
        let n = self
            .conn
            .lock()
            .execute(
                "UPDATE quarantine_items SET state = ?1, updated_at = ?2, note = COALESCE(?3, note) WHERE id = ?4",
                params![state.as_str(), ts(&Utc::now()), note, id],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Err(AegisError::NotFound(format!("quarantine item {id}")));
        }
        Ok(())
    }

    pub fn find_stored_quarantine_by_hash(&self, sha256: &str) -> Result<Option<QuarantineItem>> {
        let sql = format!("SELECT {} FROM quarantine_items WHERE sha256 = ?1 AND state = 'stored' LIMIT 1", Self::Q_COLS);
        Ok(self.conn.lock().query_row(&sql, [sha256], Self::row_quarantine).optional().map_err(db_err)?.map(|(q, _)| q))
    }

    // ------------------------------------------------------------ incidents

    pub fn upsert_incident(&self, i: &Incident) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO incidents(id, kind, severity, confidence, title, summary, process, evidence, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(id) DO UPDATE SET severity=excluded.severity, confidence=excluded.confidence,
                   title=excluded.title, summary=excluded.summary, process=excluded.process,
                   evidence=excluded.evidence, status=excluded.status, updated_at=excluded.updated_at",
                params![
                    i.id,
                    i.kind.as_str(),
                    i.severity.as_str(),
                    i.confidence as i64,
                    i.title,
                    i.summary,
                    i.process.as_ref().map(serde_json::to_string).transpose()?,
                    serde_json::to_string(&i.evidence)?,
                    i.status.as_str(),
                    ts(&i.created_at),
                    ts(&i.updated_at)
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    fn row_incident(r: &Row) -> rusqlite::Result<Incident> {
        let kind: String = r.get(1)?;
        let sev: String = r.get(2)?;
        let process: Option<String> = r.get(6)?;
        let evidence: String = r.get(7)?;
        let status: String = r.get(8)?;
        Ok(Incident {
            id: r.get(0)?,
            kind: IncidentKind::parse(&kind).unwrap_or(IncidentKind::Generic),
            severity: Severity::parse(&sev).unwrap_or(Severity::Medium),
            confidence: r.get::<_, i64>(3)?.clamp(0, 100) as u8,
            title: r.get(4)?,
            summary: r.get(5)?,
            process: process.and_then(|p| serde_json::from_str(&p).ok()),
            evidence: serde_json::from_str(&evidence).unwrap_or_default(),
            status: IncidentStatus::parse(&status).unwrap_or(IncidentStatus::Open),
            created_at: parse_ts(&r.get::<_, String>(9)?),
            updated_at: parse_ts(&r.get::<_, String>(10)?),
        })
    }

    const I_COLS: &'static str = "id, kind, severity, confidence, title, summary, process, evidence, status, created_at, updated_at";

    pub fn get_incident(&self, id: &str) -> Result<Option<Incident>> {
        let sql = format!("SELECT {} FROM incidents WHERE id = ?1", Self::I_COLS);
        self.conn.lock().query_row(&sql, [id], Self::row_incident).optional().map_err(db_err)
    }

    pub fn list_incidents(&self, status: Option<IncidentStatus>, limit: u32) -> Result<Vec<Incident>> {
        let sql = format!(
            "SELECT {} FROM incidents WHERE (?1 IS NULL OR status = ?1) ORDER BY updated_at DESC LIMIT ?2",
            Self::I_COLS
        );
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(params![status.map(|s| s.as_str()), limit.clamp(1, 1000) as i64], Self::row_incident)
            .map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    pub fn count_open_incidents(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM incidents WHERE status IN ('open','acknowledged')", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }

    // ------------------------------------------------------------ audit / updates

    pub fn audit(&self, actor: &str, action: &str, target: Option<&str>, allowed: bool, result: &str, detail: Option<&str>) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO audit_logs(ts, actor, action, target, allowed, result, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![ts(&Utc::now()), actor, action, target, allowed as i64, result, detail],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn audit_count(&self) -> Result<u64> {
        let n: i64 = self.conn.lock().query_row("SELECT COUNT(*) FROM audit_logs", [], |r| r.get(0)).map_err(db_err)?;
        Ok(n as u64)
    }

    pub fn record_update(&self, component: &str, from: Option<&str>, to: Option<&str>, success: bool, message: &str) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO update_history(ts, component, from_version, to_version, success, message) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![ts(&Utc::now()), component, from, to, success as i64, message],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn list_updates(&self, limit: u32) -> Result<Vec<UpdateRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT id, ts, component, from_version, to_version, success, message FROM update_history ORDER BY id DESC LIMIT ?1")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([limit.clamp(1, 500) as i64], |r| {
                Ok(UpdateRecord {
                    id: r.get(0)?,
                    ts: parse_ts(&r.get::<_, String>(1)?),
                    component: r.get(2)?,
                    from_version: r.get(3)?,
                    to_version: r.get(4)?,
                    success: r.get::<_, i64>(5)? != 0,
                    message: r.get(6)?,
                })
            })
            .map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    pub fn upsert_module(&self, m: &ModuleStatus) -> Result<()> {
        let id = serde_json::to_value(m.id)?.as_str().unwrap_or("unknown").to_string();
        let state = serde_json::to_value(m.state)?.as_str().unwrap_or("error").to_string();
        self.conn
            .lock()
            .execute(
                "INSERT INTO security_modules(id, state, detail, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET state=excluded.state, detail=excluded.detail, updated_at=excluded.updated_at",
                params![id, state, m.detail, ts(&m.updated_at)],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn record_model_version(&self, version: &str, sha256: &str, metrics: &str, decisions_enabled: bool) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT OR REPLACE INTO model_versions(version, sha256, installed_at, metrics, decisions_enabled) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![version, sha256, ts(&Utc::now()), metrics, decisions_enabled as i64],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn record_network_alert(&self, remote: &str, process: Option<&str>, reputation: &str, reason: Option<&str>) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO network_alerts(ts, remote, process, reputation, reason) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ts(&Utc::now()), remote, process, reputation, reason],
            )
            .map_err(db_err)?;
        Ok(())
    }

    // ------------------------------------------------------------ domain rules / IPs

    pub fn add_domain_rule(&self, r: &DomainRule) -> Result<()> {
        let list = if r.list == DomainList::Allow { "allow" } else { "block" };
        self.conn
            .lock()
            .execute(
                "INSERT INTO domain_rules(domain, list, added_at, note) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(domain) DO UPDATE SET list=excluded.list, note=excluded.note",
                params![r.domain, list, ts(&r.added_at), r.note],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn remove_domain_rule(&self, domain: &str) -> Result<bool> {
        Ok(self.conn.lock().execute("DELETE FROM domain_rules WHERE domain = ?1", [domain]).map_err(db_err)? > 0)
    }

    pub fn list_domain_rules(&self) -> Result<Vec<DomainRule>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT domain, list, added_at, note FROM domain_rules ORDER BY domain").map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                let list: String = r.get(1)?;
                Ok(DomainRule {
                    domain: r.get(0)?,
                    list: if list == "allow" { DomainList::Allow } else { DomainList::Block },
                    added_at: parse_ts(&r.get::<_, String>(2)?),
                    note: r.get(3)?,
                })
            })
            .map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    pub fn add_blocked_ip(&self, ip: &str, rule_name: &str) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT OR REPLACE INTO blocked_ips(ip, rule_name, added_at) VALUES (?1, ?2, ?3)",
                params![ip, rule_name, ts(&Utc::now())],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn remove_blocked_ip(&self, ip: &str) -> Result<Option<String>> {
        let conn = self.conn.lock();
        let name: Option<String> = conn
            .query_row("SELECT rule_name FROM blocked_ips WHERE ip = ?1", [ip], |r| r.get(0))
            .optional()
            .map_err(db_err)?;
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?1", [ip]).map_err(db_err)?;
        Ok(name)
    }

    pub fn list_blocked_ips(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT ip FROM blocked_ips ORDER BY ip").map_err(db_err)?;
        let rows = stmt.query_map([], |r| r.get(0)).map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    // ------------------------------------------------------------ startup

    /// Record that a startup item was seen; returns its first-seen time and
    /// whether it is new since the baseline was established.
    pub fn touch_startup_item(&self, id: &str, command: &str, baseline_exists: bool) -> Result<(Timestamp, bool)> {
        let now = Utc::now();
        let conn = self.conn.lock();
        let existing: Option<(String, String)> = conn
            .query_row("SELECT first_seen, command FROM startup_baseline WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
            .map_err(db_err)?;
        match existing {
            Some((first, _)) => {
                conn.execute("UPDATE startup_baseline SET last_seen = ?1, command = ?2 WHERE id = ?3", params![ts(&now), command, id])
                    .map_err(db_err)?;
                Ok((parse_ts(&first), false))
            }
            None => {
                conn.execute(
                    "INSERT INTO startup_baseline(id, first_seen, last_seen, command) VALUES (?1, ?2, ?2, ?3)",
                    params![id, ts(&now), command],
                )
                .map_err(db_err)?;
                Ok((now, baseline_exists))
            }
        }
    }

    pub fn startup_baseline_count(&self) -> Result<u64> {
        let n: i64 = self.conn.lock().query_row("SELECT COUNT(*) FROM startup_baseline", [], |r| r.get(0)).map_err(db_err)?;
        Ok(n as u64)
    }

    pub fn insert_startup_backup(&self, b: &StartupBackupRow) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO startup_backups(id, item_id, item_name, container, hive, value_name, value, value_type, created_at, restored)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                params![
                    b.backup.id,
                    b.item_id,
                    b.backup.item_name,
                    b.backup.container,
                    b.hive,
                    b.value_name,
                    b.backup.value,
                    b.value_type as i64,
                    ts(&b.backup.created_at)
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn list_startup_backups(&self) -> Result<Vec<StartupBackupRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT id, item_id, item_name, container, hive, value_name, value, value_type, created_at, restored FROM startup_backups ORDER BY created_at DESC")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StartupBackupRow {
                    backup: StartupBackup {
                        id: r.get(0)?,
                        item_name: r.get(2)?,
                        container: r.get(3)?,
                        value: r.get(6)?,
                        created_at: parse_ts(&r.get::<_, String>(8)?),
                        restored: r.get::<_, i64>(9)? != 0,
                    },
                    item_id: r.get(1)?,
                    hive: r.get(4)?,
                    value_name: r.get(5)?,
                    value_type: r.get::<_, i64>(7)? as u32,
                })
            })
            .map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    pub fn mark_startup_backup_restored(&self, id: &str) -> Result<()> {
        self.conn.lock().execute("UPDATE startup_backups SET restored = 1 WHERE id = ?1", [id]).map_err(db_err)?;
        Ok(())
    }

    // ------------------------------------------------------------ scan cache

    /// Returns true if the file (path,size,mtime) was already found clean by
    /// the same engine version (rules + hash DB + heuristics version).
    pub fn cache_is_clean(&self, path: &str, size: u64, mtime: i64, engine_version: &str) -> Result<bool> {
        let n: i64 = self
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM scan_cache WHERE path = ?1 AND size = ?2 AND mtime = ?3 AND engine_version = ?4",
                params![path, size as i64, mtime, engine_version],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        Ok(n > 0)
    }

    pub fn cache_mark_clean(&self, path: &str, size: u64, mtime: i64, engine_version: &str, sha256: Option<&str>) -> Result<()> {
        self.conn
            .lock()
            .execute(
                "INSERT OR REPLACE INTO scan_cache(path, size, mtime, engine_version, sha256, checked_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![path, size as i64, mtime, engine_version, sha256, ts(&Utc::now())],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn cache_invalidate(&self, path: &str) -> Result<()> {
        self.conn.lock().execute("DELETE FROM scan_cache WHERE path = ?1", [path]).map_err(db_err)?;
        Ok(())
    }

    /// Bound the cache size and drop entries from older engine versions.
    pub fn cache_prune(&self, engine_version: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM scan_cache WHERE engine_version != ?1", [engine_version]).map_err(db_err)?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM scan_cache", [], |r| r.get(0)).map_err(db_err)?;
        if n > MAX_CACHE_ROWS {
            conn.execute(
                "DELETE FROM scan_cache WHERE path IN (SELECT path FROM scan_cache ORDER BY checked_at ASC LIMIT ?1)",
                [n - MAX_CACHE_ROWS],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    /// Delete all user-visible history (events, scans, resolved threats).
    pub fn delete_all_history(&self) -> Result<u64> {
        let conn = self.conn.lock();
        let mut n = 0;
        n += conn.execute("DELETE FROM threat_events", []).map_err(db_err)?;
        n += conn.execute("DELETE FROM scan_jobs WHERE state IN ('completed','cancelled','failed')", []).map_err(db_err)?;
        n += conn
            .execute("DELETE FROM scan_results WHERE status IN ('deleted','resolved','ignored','restored')", [])
            .map_err(db_err)?;
        n += conn.execute("DELETE FROM network_alerts", []).map_err(db_err)?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_threat(id: &str, status: ThreatStatus) -> ThreatRecord {
        ThreatRecord {
            id: id.into(),
            job_id: Some("job1".into()),
            path: r"C:\t\a.exe".into(),
            sha256: Some("ab".repeat(32)),
            file_size: Some(10),
            verdict: Verdict::Malicious,
            severity: Severity::High,
            name: "Test".into(),
            detections: vec![],
            status,
            detected_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn migrations_apply_and_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.db");
        {
            let (s, rep) = Storage::open(&p).unwrap();
            assert!(!rep.recovered_from_corruption);
            assert_eq!(s.schema_version().unwrap(), 1);
        }
        let (s, _) = Storage::open(&p).unwrap();
        assert_eq!(s.schema_version().unwrap(), 1);
        assert!(s.integrity_ok());
    }

    #[test]
    fn corrupt_database_is_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.db");
        std::fs::write(&p, b"this is definitely not a sqlite database file at all, garbage garbage").unwrap();
        let (s, rep) = Storage::open(&p).unwrap();
        assert!(rep.recovered_from_corruption);
        assert!(rep.corrupt_backup.unwrap().exists());
        assert!(s.integrity_ok());
    }

    #[test]
    fn settings_roundtrip() {
        let s = Storage::open_in_memory().unwrap();
        let mut st = s.load_settings().unwrap();
        assert!(!st.telemetry_enabled, "telemetry must default to off");
        st.gaming_mode = true;
        s.save_settings(&st).unwrap();
        assert!(s.load_settings().unwrap().gaming_mode);
    }

    #[test]
    fn events_paging_and_filters() {
        let s = Storage::open_in_memory().unwrap();
        for i in 0..30 {
            let sev = if i % 3 == 0 { Severity::High } else { Severity::Info };
            s.insert_event(&NewEvent::new(EventCategory::Scan, sev, "k", format!("t{i}"), "m")).unwrap();
        }
        let first = s.list_events(None, None, None, 10).unwrap();
        assert_eq!(first.len(), 10);
        let next = s.list_events(None, None, Some(first.last().unwrap().id), 10).unwrap();
        assert!(next[0].id < first.last().unwrap().id);
        let high = s.list_events(None, Some(Severity::High), None, 100).unwrap();
        assert_eq!(high.len(), 10);
        let stats = s.history_stats(7).unwrap();
        assert_eq!(stats.days.len(), 7);
        assert_eq!(stats.by_category.get("scan"), Some(&30));
    }

    #[test]
    fn threats_and_fp_override() {
        let s = Storage::open_in_memory().unwrap();
        s.insert_threat(&sample_threat("t1", ThreatStatus::Active)).unwrap();
        assert_eq!(s.count_threats(Some(ThreatStatus::Active)).unwrap(), 1);
        assert!(s.find_active_threat(r"C:\t\a.exe", Some(&"ab".repeat(32))).unwrap().is_some());
        s.set_threat_status("t1", ThreatStatus::Allowed).unwrap();
        assert!(s.is_hash_allowed(&"ab".repeat(32)).unwrap());
        assert!(s.set_threat_status("missing", ThreatStatus::Allowed).is_err());
    }

    #[test]
    fn interrupted_jobs_marked_failed() {
        let s = Storage::open_in_memory().unwrap();
        s.upsert_scan_job(&ScanJobSummary {
            job_id: "j".into(),
            kind: ScanKind::Quick,
            state: ScanState::Running,
            targets: vec![],
            counters: Default::default(),
            started_at: Utc::now(),
            finished_at: None,
            error: None,
        })
        .unwrap();
        assert_eq!(s.fail_interrupted_jobs().unwrap(), 1);
        assert_eq!(s.list_scan_jobs(5).unwrap()[0].state, ScanState::Failed);
    }

    #[test]
    fn scan_cache_versioned() {
        let s = Storage::open_in_memory().unwrap();
        s.cache_mark_clean("C:\\a", 1, 2, "v1", None).unwrap();
        assert!(s.cache_is_clean("C:\\a", 1, 2, "v1").unwrap());
        assert!(!s.cache_is_clean("C:\\a", 1, 3, "v1").unwrap());
        assert!(!s.cache_is_clean("C:\\a", 1, 2, "v2").unwrap());
        s.cache_prune("v2").unwrap();
        assert!(!s.cache_is_clean("C:\\a", 1, 2, "v1").unwrap());
    }
}

