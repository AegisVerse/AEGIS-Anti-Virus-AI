-- AEGIS AI Security schema v1
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_rank INTEGER NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT 'null'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON threat_events(ts);
CREATE INDEX IF NOT EXISTS idx_events_cat ON threat_events(category, id);
CREATE INDEX IF NOT EXISTS idx_events_sev ON threat_events(severity_rank, id);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    targets TEXT NOT NULL,
    counters TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_started ON scan_jobs(started_at);

CREATE TABLE IF NOT EXISTS scan_results (
    threat_id TEXT PRIMARY KEY,
    job_id TEXT,
    path TEXT NOT NULL,
    sha256 TEXT,
    file_size INTEGER,
    verdict TEXT NOT NULL,
    severity TEXT NOT NULL,
    name TEXT NOT NULL,
    detections TEXT NOT NULL,
    status TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_status ON scan_results(status);
CREATE INDEX IF NOT EXISTS idx_results_sha ON scan_results(sha256);
CREATE INDEX IF NOT EXISTS idx_results_detected ON scan_results(detected_at);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    process TEXT,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, updated_at);

CREATE TABLE IF NOT EXISTS quarantine_items (
    id TEXT PRIMARY KEY,
    threat_id TEXT,
    original_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    threat_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    state TEXT NOT NULL,
    xor_key TEXT NOT NULL,
    vault_file TEXT NOT NULL,
    quarantined_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_quarantine_sha ON quarantine_items(sha256, state);

CREATE TABLE IF NOT EXISTS security_modules (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    detail TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS update_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    component TEXT NOT NULL,
    from_version TEXT,
    to_version TEXT,
    success INTEGER NOT NULL,
    message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    last_hit TEXT
);

CREATE TABLE IF NOT EXISTS model_versions (
    version TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    metrics TEXT NOT NULL,
    decisions_enabled INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS network_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    remote TEXT NOT NULL,
    process TEXT,
    reputation TEXT NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    allowed INTEGER NOT NULL,
    result TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);

CREATE TABLE IF NOT EXISTS domain_rules (
    domain TEXT PRIMARY KEY,
    list TEXT NOT NULL,
    added_at TEXT NOT NULL,
    note TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    rule_name TEXT NOT NULL,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS startup_baseline (
    id TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    command TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS startup_backups (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    item_name TEXT NOT NULL,
    container TEXT NOT NULL,
    hive TEXT NOT NULL,
    value_name TEXT NOT NULL,
    value TEXT NOT NULL,
    value_type INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    restored INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_cache (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    engine_version TEXT NOT NULL,
    sha256 TEXT,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_checked ON scan_cache(checked_at);

