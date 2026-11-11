//! Data model shared across the service, the desktop bridge and the UI.
//! Field names are snake_case on the wire; the TypeScript mirror lives in
//! `apps/desktop/src/types/aegis.ts` and must be kept in sync.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Timestamp = DateTime<Utc>;

// ---------------------------------------------------------------- modules

/// Honest operational state of a protection module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    Active,
    Disabled,
    Unavailable,
    NotInstalled,
    Experimental,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    FileScanner,
    YaraEngine,
    HashReputation,
    Heuristics,
    ClamAv,
    RealTimeFiles,
    ProcessMonitor,
    BehaviorCorrelation,
    MemoryGuardian,
    RansomwareShield,
    NetworkSentinel,
    DomainProtection,
    StartupGuardian,
    UsbSecurity,
    SystemAudit,
    AiClassifier,
    AiAnalyst,
    Quarantine,
    Scheduler,
    Updater,
    EventLogTelemetry,
    Sysmon,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub id: ModuleId,
    pub state: ModuleState,
    /// Short technical explanation (English; UI localizes known ids).
    pub detail: String,
    pub updated_at: Timestamp,
}

// ---------------------------------------------------------------- detection

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    Yara,
    HashReputation,
    Heuristic,
    ClamAv,
    AiModel,
    Behavior,
    Archive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Detection {
    pub source: DetectionSource,
    /// Stable identifier of the rule/signature (e.g. YARA rule identifier).
    pub rule_id: String,
    /// Display name of the threat / indicator.
    pub name: String,
    pub severity: Severity,
    /// 0..=100 confidence that this indicator is truly malicious.
    pub confidence: u8,
    pub description: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------- scanning

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    Quick,
    Full,
    Custom,
    Usb,
    RealTime,
    ContextMenu,
    Scheduled,
}

impl ScanKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanKind::Quick => "quick",
            ScanKind::Full => "full",
            ScanKind::Custom => "custom",
            ScanKind::Usb => "usb",
            ScanKind::RealTime => "real_time",
            ScanKind::ContextMenu => "context_menu",
            ScanKind::Scheduled => "scheduled",
        }
    }
    pub fn parse(s: &str) -> Option<ScanKind> {
        Some(match s {
            "quick" => ScanKind::Quick,
            "full" => ScanKind::Full,
            "custom" => ScanKind::Custom,
            "usb" => ScanKind::Usb,
            "real_time" => ScanKind::RealTime,
            "context_menu" => ScanKind::ContextMenu,
            "scheduled" => ScanKind::Scheduled,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Queued,
    Running,
    Paused,
    Cancelling,
    Cancelled,
    Completed,
    Failed,
}

impl ScanState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, ScanState::Cancelled | ScanState::Completed | ScanState::Failed)
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanState::Queued => "queued",
            ScanState::Running => "running",
            ScanState::Paused => "paused",
            ScanState::Cancelling => "cancelling",
            ScanState::Cancelled => "cancelled",
            ScanState::Completed => "completed",
            ScanState::Failed => "failed",
        }
    }
    pub fn parse(s: &str) -> Option<ScanState> {
        Some(match s {
            "queued" => ScanState::Queued,
            "running" => ScanState::Running,
            "paused" => ScanState::Paused,
            "cancelling" => ScanState::Cancelling,
            "cancelled" => ScanState::Cancelled,
            "completed" => ScanState::Completed,
            "failed" => ScanState::Failed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanCounters {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub threats_found: u64,
    pub suspicious_found: u64,
    pub skipped: u64,
    pub errors: u64,
    pub archives_scanned: u64,
    pub cache_hits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub job_id: String,
    pub kind: ScanKind,
    pub state: ScanState,
    pub targets: Vec<String>,
    pub current_target: Option<String>,
    pub counters: ScanCounters,
    /// Files discovered so far by the enumerator (may grow during scan).
    pub files_discovered: u64,
    /// True once enumeration finished, so `files_discovered` is final.
    pub enumeration_complete: bool,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub elapsed_ms: u64,
    pub error: Option<String>,
    /// Up to 50 most recent skip/error reasons for transparency.
    pub recent_issues: Vec<ScanIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIssue {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJobSummary {
    pub job_id: String,
    pub kind: ScanKind,
    pub state: ScanState,
    pub targets: Vec<String>,
    pub counters: ScanCounters,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------- threats

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatStatus {
    Active,
    Quarantined,
    Allowed,
    Ignored,
    Restored,
    Deleted,
    Resolved,
}

impl ThreatStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatStatus::Active => "active",
            ThreatStatus::Quarantined => "quarantined",
            ThreatStatus::Allowed => "allowed",
            ThreatStatus::Ignored => "ignored",
            ThreatStatus::Restored => "restored",
            ThreatStatus::Deleted => "deleted",
            ThreatStatus::Resolved => "resolved",
        }
    }
    pub fn parse(s: &str) -> Option<ThreatStatus> {
        Some(match s {
            "active" => ThreatStatus::Active,
            "quarantined" => ThreatStatus::Quarantined,
            "allowed" => ThreatStatus::Allowed,
            "ignored" => ThreatStatus::Ignored,
            "restored" => ThreatStatus::Restored,
            "deleted" => ThreatStatus::Deleted,
            "resolved" => ThreatStatus::Resolved,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRecord {
    pub id: String,
    pub job_id: Option<String>,
    pub path: String,
    pub sha256: Option<String>,
    pub file_size: Option<u64>,
    pub verdict: Verdict,
    pub severity: Severity,
    /// Primary display name (strongest detection).
    pub name: String,
    pub detections: Vec<Detection>,
    pub status: ThreatStatus,
    pub detected_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatAction {
    Quarantine,
    Allow,
    Ignore,
}

// ---------------------------------------------------------------- quarantine

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineState {
    /// Being moved into the vault (crash recovery checks this state).
    Pending,
    Stored,
    Restored,
    Deleted,
    Failed,
}

impl QuarantineState {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuarantineState::Pending => "pending",
            QuarantineState::Stored => "stored",
            QuarantineState::Restored => "restored",
            QuarantineState::Deleted => "deleted",
            QuarantineState::Failed => "failed",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "stored" => Self::Stored,
            "restored" => Self::Restored,
            "deleted" => Self::Deleted,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub threat_id: Option<String>,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub threat_name: String,
    pub severity: Severity,
    pub state: QuarantineState,
    pub quarantined_at: Timestamp,
    pub updated_at: Timestamp,
    pub note: Option<String>,
}

// ---------------------------------------------------------------- events

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Scan,
    Threat,
    Quarantine,
    RealTime,
    Process,
    Persistence,
    Network,
    Domain,
    Usb,
    Ransomware,
    Memory,
    Behavior,
    Audit,
    Update,
    Policy,
    System,
    Ai,
}

impl EventCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventCategory::Scan => "scan",
            EventCategory::Threat => "threat",
            EventCategory::Quarantine => "quarantine",
            EventCategory::RealTime => "real_time",
            EventCategory::Process => "process",
            EventCategory::Persistence => "persistence",
            EventCategory::Network => "network",
            EventCategory::Domain => "domain",
            EventCategory::Usb => "usb",
            EventCategory::Ransomware => "ransomware",
            EventCategory::Memory => "memory",
            EventCategory::Behavior => "behavior",
            EventCategory::Audit => "audit",
            EventCategory::Update => "update",
            EventCategory::Policy => "policy",
            EventCategory::System => "system",
            EventCategory::Ai => "ai",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "scan" => Self::Scan,
            "threat" => Self::Threat,
            "quarantine" => Self::Quarantine,
            "real_time" => Self::RealTime,
            "process" => Self::Process,
            "persistence" => Self::Persistence,
            "network" => Self::Network,
            "domain" => Self::Domain,
            "usb" => Self::Usb,
            "ransomware" => Self::Ransomware,
            "memory" => Self::Memory,
            "behavior" => Self::Behavior,
            "audit" => Self::Audit,
            "update" => Self::Update,
            "policy" => Self::Policy,
            "system" => Self::System,
            "ai" => Self::Ai,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub ts: Timestamp,
    pub category: EventCategory,
    pub severity: Severity,
    /// Machine-readable event kind, e.g. `scan.completed`.
    pub kind: String,
    pub title: String,
    pub message: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

/// An event before it gets an id from storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewEvent {
    pub category: EventCategory,
    pub severity: Severity,
    pub kind: String,
    pub title: String,
    pub message: String,
    pub data: serde_json::Value,
}

impl NewEvent {
    pub fn new(
        category: EventCategory,
        severity: Severity,
        kind: impl Into<String>,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity,
            kind: kind.into(),
            title: title.into(),
            message: message.into(),
            data: serde_json::Value::Null,
        }
    }
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }
}

// ---------------------------------------------------------------- incidents

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentKind {
    RemoteAccessTrojan,
    Spyware,
    Ransomware,
    Persistence,
    SuspiciousScript,
    SecurityTampering,
    MemoryTampering,
    Adware,
    NetworkThreat,
    Generic,
}

impl IncidentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RemoteAccessTrojan => "remote_access_trojan",
            Self::Spyware => "spyware",
            Self::Ransomware => "ransomware",
            Self::Persistence => "persistence",
            Self::SuspiciousScript => "suspicious_script",
            Self::SecurityTampering => "security_tampering",
            Self::MemoryTampering => "memory_tampering",
            Self::Adware => "adware",
            Self::NetworkThreat => "network_threat",
            Self::Generic => "generic",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "remote_access_trojan" => Self::RemoteAccessTrojan,
            "spyware" => Self::Spyware,
            "ransomware" => Self::Ransomware,
            "persistence" => Self::Persistence,
            "suspicious_script" => Self::SuspiciousScript,
            "security_tampering" => Self::SecurityTampering,
            "memory_tampering" => Self::MemoryTampering,
            "adware" => Self::Adware,
            "network_threat" => Self::NetworkThreat,
            "generic" => Self::Generic,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Acknowledged,
    Resolved,
    FalsePositive,
}

impl IncidentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
            Self::FalsePositive => "false_positive",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "open" => Self::Open,
            "acknowledged" => Self::Acknowledged,
            "resolved" => Self::Resolved,
            "false_positive" => Self::FalsePositive,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    /// Id of the stored security event that supports this indicator.
    pub event_id: Option<i64>,
    pub indicator: String,
    pub weight: u8,
    pub detail: String,
    pub ts: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub kind: IncidentKind,
    pub severity: Severity,
    /// 0..=100
    pub confidence: u8,
    pub title: String,
    pub summary: String,
    pub process: Option<ProcessInfo>,
    pub evidence: Vec<Evidence>,
    pub status: IncidentStatus,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

// ---------------------------------------------------------------- processes

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    Invalid,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureInfo {
    pub status: SignatureStatus,
    pub publisher: Option<String>,
}

impl SignatureInfo {
    pub fn unknown() -> Self {
        Self { status: SignatureStatus::Unknown, publisher: None }
    }
    pub fn is_trusted(&self) -> bool {
        self.status == SignatureStatus::Valid
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub command_line: Option<String>,
    pub signature: Option<SignatureInfo>,
    pub parent_name: Option<String>,
    pub session_id: Option<u32>,
    pub working_set_bytes: Option<u64>,
    pub first_seen: Timestamp,
    /// Indicators raised by the process monitor (not verdicts).
    #[serde(default)]
    pub flags: Vec<String>,
    /// True if the process is on the critical-process list and must never
    /// be suspended or terminated by AEGIS.
    #[serde(default)]
    pub critical: bool,
}

// ---------------------------------------------------------------- network

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reputation {
    KnownMalicious,
    Suspicious,
    Unknown,
    Trusted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub pid: u32,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub reputation: Reputation,
    pub reputation_reason: Option<String>,
    pub is_private_remote: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainList {
    /// User allowlist (always wins).
    Allow,
    /// User blocklist.
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRule {
    pub domain: String,
    pub list: DomainList,
    pub added_at: Timestamp,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCheck {
    pub domain: String,
    pub reputation: Reputation,
    pub category: Option<String>,
    pub matched_rule: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainProtectionStatus {
    pub lists: Vec<DomainListInfo>,
    pub user_rules: Vec<DomainRule>,
    pub hosts_enforcement: ModuleState,
    pub hosts_enforcement_detail: String,
    pub enforced_domain_count: u64,
    pub blocked_ips: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainListInfo {
    pub name: String,
    pub category: String,
    pub entries: u64,
    pub source: String,
    pub license: String,
    pub enabled: bool,
}

// ---------------------------------------------------------------- startup

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupLocation {
    RegistryRun,
    RegistryRunOnce,
    StartupFolder,
    ScheduledTask,
    Service,
    Winlogon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Trusted,
    Unknown,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    /// Stable id: sha256(location|scope|key|name)[..16].
    pub id: String,
    pub location: StartupLocation,
    /// `user` or `machine`
    pub scope: String,
    /// Registry key path, folder path or task path.
    pub container: String,
    pub name: String,
    pub command: String,
    pub executable_path: Option<String>,
    pub signature: Option<SignatureInfo>,
    pub modified_at: Option<Timestamp>,
    pub first_seen: Timestamp,
    pub assessment: Assessment,
    pub indicators: Vec<String>,
    /// True if AEGIS can safely disable it (supported location + permissions).
    pub can_disable: bool,
    pub is_new: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupBackup {
    pub id: String,
    pub item_name: String,
    pub container: String,
    pub value: String,
    pub created_at: Timestamp,
    pub restored: bool,
}

// ---------------------------------------------------------------- usb

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDrive {
    pub root: String,
    pub label: Option<String>,
    pub filesystem: Option<String>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub inserted_at: Timestamp,
    pub autorun_inf: bool,
    pub suspicious_items: Vec<String>,
    pub last_scan_job: Option<String>,
    pub accessible: bool,
}

// ---------------------------------------------------------------- audit

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Pass,
    Warning,
    Fail,
    Unknown,
    RequiresElevation,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheck {
    pub id: String,
    pub category: String,
    pub title: String,
    pub status: AuditStatus,
    pub detail: String,
    pub recommendation: Option<String>,
    pub doc_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub generated_at: Timestamp,
    pub os_caption: Option<String>,
    pub os_build: Option<String>,
    pub elevated: bool,
    pub checks: Vec<AuditCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefenderStatus {
    pub available: bool,
    pub antivirus_enabled: Option<bool>,
    pub real_time_protection: Option<bool>,
    pub tamper_protection: Option<bool>,
    pub signature_version: Option<String>,
    pub signature_age_days: Option<i64>,
    pub detail: String,
}

// ---------------------------------------------------------------- ransomware / memory

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareStatus {
    pub state: ModuleState,
    pub protected_folders: Vec<String>,
    pub monitored_folders: Vec<String>,
    pub window_secs: u64,
    pub recent_bursts: Vec<RansomwareSignal>,
    pub allowlisted_processes: Vec<String>,
    pub backups_available: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareSignal {
    pub ts: Timestamp,
    pub folder: String,
    pub modified: u64,
    pub renamed: u64,
    pub deleted: u64,
    pub created: u64,
    pub extension_changes: u64,
    pub high_entropy_writes: u64,
    pub ransom_note_names: Vec<String>,
    pub score: u8,
    pub suspected_processes: Vec<ProcessIoSample>,
    pub event_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIoSample {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub write_bytes_delta: u64,
    pub write_ops_delta: u64,
    pub allowlisted: bool,
    pub critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOverview {
    pub state: ModuleState,
    pub detail: String,
    pub processes: Vec<ProcessInfo>,
    pub total_physical_bytes: u64,
    pub available_physical_bytes: u64,
    pub recent_events: Vec<SecurityEvent>,
    pub limitations: Vec<String>,
}

// ---------------------------------------------------------------- AI

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiStatus {
    pub classifier_state: ModuleState,
    pub classifier_detail: String,
    pub model_version: Option<String>,
    pub model_decisions_enabled: bool,
    pub analyst_state: ModuleState,
    pub analyst_detail: String,
    pub analyst_backend: Option<String>,
    pub analyst_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    /// `event`, `threat`, `incident`, `scan`, `quarantine`, `module`, `audit`
    pub kind: String,
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystAnswer {
    pub answer: String,
    pub sources: Vec<SourceRef>,
    /// `ollama:<model>` or `rule_based`
    pub backend: String,
    pub grounded: bool,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------- updates

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetInfo {
    pub name: String,
    pub file: String,
    pub source: String,
    pub license: String,
    pub version: String,
    pub rule_count: u64,
    pub compiled_ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRecord {
    pub id: i64,
    pub ts: Timestamp,
    pub component: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub rules_version: String,
    pub rules_loaded_at: Option<Timestamp>,
    pub rule_sets: Vec<RuleSetInfo>,
    pub hash_db_entries: u64,
    pub clamav_state: ModuleState,
    pub clamav_detail: String,
    pub app_update_channel: String,
    pub trusted_key_fingerprints: Vec<String>,
    pub history: Vec<UpdateRecord>,
}

// ---------------------------------------------------------------- settings

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoAction {
    /// Only notify; never act automatically.
    NotifyOnly,
    /// Quarantine only high-confidence malicious verdicts outside system dirs.
    QuarantineConfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Cadence {
    Daily { hour: u8, minute: u8 },
    Weekly { weekday: u8, hour: u8, minute: u8 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScheduleEntry {
    pub id: String,
    pub kind: ScanKind,
    pub cadence: Cadence,
    pub enabled: bool,
    #[serde(default)]
    pub last_run: Option<Timestamp>,
    /// Run missed schedules at next opportunity (e.g. after boot).
    #[serde(default = "default_true")]
    pub catch_up: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub language: String,
    pub theme: String,
    pub realtime_enabled: bool,
    /// When set, real-time protection is paused until this time.
    pub realtime_paused_until: Option<Timestamp>,
    pub auto_action: AutoAction,
    pub scan_archives: bool,
    pub max_archive_depth: u32,
    pub max_archive_expanded_mb: u64,
    pub max_file_size_mb: u64,
    pub scan_threads: u32,
    pub low_priority_scans: bool,
    pub exclusions: Vec<String>,
    pub schedules: Vec<ScheduleEntry>,
    pub gaming_mode: bool,
    pub gaming_mode_auto: bool,
    pub usb_scan_on_insert: bool,
    pub ransomware_enabled: bool,
    pub protected_folders: Vec<String>,
    pub ransomware_allowlist: Vec<String>,
    pub process_monitor_enabled: bool,
    pub network_monitor_enabled: bool,
    pub hosts_blocking_enabled: bool,
    pub ad_blocklist_enabled: bool,
    pub clamav_enabled: bool,
    pub clamav_path: Option<String>,
    pub analyst_enabled: bool,
    pub analyst_endpoint: String,
    pub analyst_model: String,
    pub notifications_enabled: bool,
    pub telemetry_enabled: bool,
    pub event_retention_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            language: "tr".into(),
            theme: "dark".into(),
            realtime_enabled: true,
            realtime_paused_until: None,
            auto_action: AutoAction::NotifyOnly,
            scan_archives: true,
            max_archive_depth: 3,
            max_archive_expanded_mb: 256,
            max_file_size_mb: 128,
            scan_threads: 0,
            low_priority_scans: true,
            exclusions: vec![],
            schedules: vec![
                ScheduleEntry {
                    id: "daily-quick".into(),
                    kind: ScanKind::Quick,
                    cadence: Cadence::Daily { hour: 12, minute: 0 },
                    enabled: true,
                    last_run: None,
                    catch_up: true,
                },
                ScheduleEntry {
                    id: "weekly-full".into(),
                    kind: ScanKind::Full,
                    cadence: Cadence::Weekly { weekday: 6, hour: 3, minute: 0 },
                    enabled: false,
                    last_run: None,
                    catch_up: false,
                },
            ],
            gaming_mode: false,
            gaming_mode_auto: true,
            usb_scan_on_insert: false,
            ransomware_enabled: true,
            protected_folders: vec![],
            ransomware_allowlist: vec![],
            process_monitor_enabled: true,
            network_monitor_enabled: true,
            hosts_blocking_enabled: false,
            ad_blocklist_enabled: false,
            clamav_enabled: true,
            clamav_path: None,
            analyst_enabled: true,
            analyst_endpoint: "http://127.0.0.1:11434".into(),
            analyst_model: "llama3.2:3b".into(),
            notifications_enabled: true,
            telemetry_enabled: false,
            event_retention_days: 90,
        }
    }
}

// ---------------------------------------------------------------- dashboard / diagnostics

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub service_cpu_percent: Option<f32>,
    pub service_working_set_bytes: Option<u64>,
    pub service_private_bytes: Option<u64>,
    pub system_memory_load_percent: Option<u32>,
    pub measured_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub overall: OverallProtection,
    pub service_mode: String,
    pub elevated: bool,
    pub modules: Vec<ModuleStatus>,
    pub defender: DefenderStatus,
    pub last_scan: Option<ScanJobSummary>,
    pub active_scan: Option<ScanProgress>,
    pub active_threats: u64,
    pub total_detections: u64,
    pub quarantine_count: u64,
    pub open_incidents: u64,
    pub last_rules_update: Option<Timestamp>,
    pub rules_version: String,
    pub recent_events: Vec<SecurityEvent>,
    pub critical_alerts: Vec<SecurityEvent>,
    pub coverage_warnings: Vec<String>,
    pub resources: ResourceUsage,
    pub gaming_mode_active: bool,
    pub realtime_paused_until: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallProtection {
    /// Core modules active, no unresolved threats.
    Protected,
    /// Some modules reduced/paused or warnings present.
    Reduced,
    /// Active threats or open critical incidents.
    AtRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostics {
    pub version: String,
    pub protocol_version: u32,
    pub service_mode: String,
    pub elevated: bool,
    pub data_dir: String,
    pub quarantine_dir: String,
    pub rules_dir: String,
    pub log_dir: String,
    pub db_path: String,
    pub db_size_bytes: u64,
    pub db_integrity_ok: bool,
    pub os: String,
    pub uptime_secs: u64,
    pub modules: Vec<ModuleStatus>,
    pub build_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryStats {
    pub days: Vec<DayStat>,
    pub by_category: BTreeMap<String, u64>,
    pub by_severity: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayStat {
    pub day: String,
    pub events: u64,
    pub threats: u64,
    pub scans: u64,
}

