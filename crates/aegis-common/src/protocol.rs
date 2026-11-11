//! IPC protocol between the desktop bridge and the security service.
//!
//! Framing (see `aegis-ipc`): 4-byte little-endian length + UTF-8 JSON.
//! Every request is a tagged enum; unknown commands are rejected by serde.

use crate::error::ErrorCode;
use crate::types::*;
use serde::{Deserialize, Serialize};

/// Maximum size of a single IPC frame (requests and responses).
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// Maximum size of a request frame from a client.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u32,
    pub client_name: String,
    pub client_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub protocol_version: u32,
    pub service_version: String,
    pub service_mode: String,
    /// Whether this connection may perform privileged (state-changing) commands.
    pub privileged_allowed: bool,
    pub client_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "args", rename_all = "snake_case")]
pub enum Request {
    Ping,
    GetDashboard,
    GetModules,
    GetDiagnostics,

    // scanning
    StartScan { kind: ScanKind, #[serde(default)] paths: Vec<String> },
    CancelScan { job_id: String },
    PauseScan { job_id: String },
    ResumeScan { job_id: String },
    GetScanProgress { job_id: Option<String> },
    ListScanJobs { limit: u32 },

    // threats & quarantine
    ListThreats { status: Option<ThreatStatus>, limit: u32 },
    ThreatAction { threat_id: String, action: ThreatAction },
    ListQuarantine,
    RestoreQuarantine {
        id: String,
        /// Must be true to restore an item whose verdict was malicious.
        #[serde(default)]
        accept_risk: bool,
        /// Optional alternative destination directory.
        #[serde(default)]
        destination_dir: Option<String>,
    },
    DeleteQuarantine { id: String },

    // events / incidents / history
    ListEvents {
        category: Option<EventCategory>,
        min_severity: Option<Severity>,
        before_id: Option<i64>,
        limit: u32,
    },
    ListIncidents { status: Option<IncidentStatus>, limit: u32 },
    UpdateIncident { id: String, status: IncidentStatus },
    GetHistoryStats { days: u32 },
    ExportReport,
    DeleteHistory { older_than_days: u32 },

    // settings & protection control
    GetSettings,
    UpdateSettings { settings: Settings },
    SetRealtime { enabled: bool, pause_minutes: Option<u32> },
    SetGamingMode { enabled: bool },

    // processes / memory / ransomware
    ListProcesses,
    GetMemoryOverview,
    SuspendProcess { pid: u32, incident_id: Option<String>, confirm: bool },
    ResumeProcess { pid: u32 },
    GetRansomwareStatus,

    // network & domains
    ListConnections,
    GetDomainStatus,
    CheckDomain { domain: String },
    AddDomainRule { domain: String, list: DomainList, note: Option<String> },
    RemoveDomainRule { domain: String },
    SetHostsBlocking { enabled: bool },
    BlockIp { ip: String, confirm: bool },
    UnblockIp { ip: String },

    // startup / usb / audit
    ListStartupItems,
    DisableStartupItem { id: String, confirm: bool },
    ListStartupBackups,
    RestoreStartupItem { backup_id: String },
    ListUsbDrives,
    ScanUsb { root: String },
    RunAudit,

    // AI
    GetAiStatus,
    AskAnalyst { question: String, language: String },

    // updates
    GetUpdateStatus,
    ReloadRules,
    ApplyRulePack { path: String },
    UpdateClamAvDatabase,
}

impl Request {
    /// Commands that change system or protection state. These require a
    /// privileged-capable connection and are written to the audit log.
    pub fn is_state_changing(&self) -> bool {
        use Request::*;
        matches!(
            self,
            StartScan { .. }
                | CancelScan { .. }
                | PauseScan { .. }
                | ResumeScan { .. }
                | ThreatAction { .. }
                | RestoreQuarantine { .. }
                | DeleteQuarantine { .. }
                | UpdateIncident { .. }
                | DeleteHistory { .. }
                | UpdateSettings { .. }
                | SetRealtime { .. }
                | SetGamingMode { .. }
                | SuspendProcess { .. }
                | ResumeProcess { .. }
                | AddDomainRule { .. }
                | RemoveDomainRule { .. }
                | SetHostsBlocking { .. }
                | BlockIp { .. }
                | UnblockIp { .. }
                | DisableStartupItem { .. }
                | RestoreStartupItem { .. }
                | ScanUsb { .. }
                | ReloadRules
                | ApplyRulePack { .. }
                | UpdateClamAvDatabase
        )
    }

    pub fn name(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.get("cmd").and_then(|c| c.as_str().map(str::to_string)))
            .unwrap_or_else(|| "unknown".into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

impl Response {
    pub fn ok<T: Serialize>(v: &T) -> Response {
        match serde_json::to_value(v) {
            Ok(data) => Response { ok: true, data: Some(data), error: None },
            Err(e) => Response::err(ErrorCode::Internal, e.to_string()),
        }
    }
    pub fn err(code: ErrorCode, message: impl Into<String>) -> Response {
        Response { ok: false, data: None, error: Some(IpcError { code, message: message.into() }) }
    }
    pub fn from_error(e: &crate::AegisError) -> Response {
        Response::err(e.code(), e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_and_tagging() {
        let r = Request::StartScan { kind: ScanKind::Custom, paths: vec!["C:\\x".into()] };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"cmd\":\"start_scan\""));
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::StartScan { kind: ScanKind::Custom, .. }));
        assert_eq!(back.name(), "start_scan");
        assert!(back.is_state_changing());
    }

    #[test]
    fn unknown_command_rejected() {
        let r: std::result::Result<Request, _> =
            serde_json::from_str(r#"{"cmd":"run_shell","args":{"c":"whoami"}}"#);
        assert!(r.is_err());
    }

    #[test]
    fn unit_command_parses() {
        let r: Request = serde_json::from_str(r#"{"cmd":"ping"}"#).unwrap();
        assert!(matches!(r, Request::Ping));
        assert!(!r.is_state_changing());
    }
}

