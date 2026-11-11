/**
 * TypeScript mirror of `crates/aegis-common/src/types.rs` and
 * `crates/aegis-common/src/protocol.rs`. Field names are snake_case on the
 * wire. Keep in sync with the Rust definitions.
 *
 * Rust `Option<T>` serializes as `null`, so optional fields are typed `T | null`.
 * Timestamps are RFC 3339 strings (chrono `DateTime<Utc>`).
 */

export type Timestamp = string;

// ---------------------------------------------------------------- modules

export const MODULE_STATES = [
  'active',
  'disabled',
  'unavailable',
  'not_installed',
  'experimental',
  'error',
] as const;
export type ModuleState = (typeof MODULE_STATES)[number];

export const MODULE_IDS = [
  'file_scanner',
  'yara_engine',
  'hash_reputation',
  'heuristics',
  'clam_av',
  'real_time_files',
  'process_monitor',
  'behavior_correlation',
  'memory_guardian',
  'ransomware_shield',
  'network_sentinel',
  'domain_protection',
  'startup_guardian',
  'usb_security',
  'system_audit',
  'ai_classifier',
  'ai_analyst',
  'quarantine',
  'scheduler',
  'updater',
  'event_log_telemetry',
  'sysmon',
] as const;
export type ModuleId = (typeof MODULE_IDS)[number];

export interface ModuleStatus {
  id: ModuleId;
  state: ModuleState;
  detail: string;
  updated_at: Timestamp;
}

// ---------------------------------------------------------------- detection

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Verdict = 'clean' | 'suspicious' | 'malicious';

export type DetectionSource =
  | 'yara'
  | 'hash_reputation'
  | 'heuristic'
  | 'clam_av'
  | 'ai_model'
  | 'behavior'
  | 'archive';

export interface Detection {
  source: DetectionSource;
  rule_id: string;
  name: string;
  severity: Severity;
  /** 0..=100 */
  confidence: number;
  description: string;
  metadata: Record<string, string>;
}

// ---------------------------------------------------------------- scanning

export const SCAN_KINDS = [
  'quick',
  'full',
  'custom',
  'usb',
  'real_time',
  'context_menu',
  'scheduled',
] as const;
export type ScanKind = (typeof SCAN_KINDS)[number];

export const SCAN_STATES = [
  'queued',
  'running',
  'paused',
  'cancelling',
  'cancelled',
  'completed',
  'failed',
] as const;
export type ScanState = (typeof SCAN_STATES)[number];

export function isTerminalScanState(s: ScanState): boolean {
  return s === 'cancelled' || s === 'completed' || s === 'failed';
}

export interface ScanCounters {
  files_scanned: number;
  bytes_scanned: number;
  threats_found: number;
  suspicious_found: number;
  skipped: number;
  errors: number;
  archives_scanned: number;
  cache_hits: number;
}

export interface ScanIssue {
  path: string;
  reason: string;
}

export interface ScanProgress {
  job_id: string;
  kind: ScanKind;
  state: ScanState;
  targets: string[];
  current_target: string | null;
  counters: ScanCounters;
  files_discovered: number;
  enumeration_complete: boolean;
  started_at: Timestamp;
  finished_at: Timestamp | null;
  elapsed_ms: number;
  error: string | null;
  recent_issues: ScanIssue[];
}

export interface ScanJobSummary {
  job_id: string;
  kind: ScanKind;
  state: ScanState;
  targets: string[];
  counters: ScanCounters;
  started_at: Timestamp;
  finished_at: Timestamp | null;
  error: string | null;
}

// ---------------------------------------------------------------- threats

export const THREAT_STATUSES = [
  'active',
  'quarantined',
  'allowed',
  'ignored',
  'restored',
  'deleted',
  'resolved',
] as const;
export type ThreatStatus = (typeof THREAT_STATUSES)[number];

export interface ThreatRecord {
  id: string;
  job_id: string | null;
  path: string;
  sha256: string | null;
  file_size: number | null;
  verdict: Verdict;
  severity: Severity;
  name: string;
  detections: Detection[];
  status: ThreatStatus;
  detected_at: Timestamp;
  updated_at: Timestamp;
}

export type ThreatAction = 'quarantine' | 'allow' | 'ignore';

// ---------------------------------------------------------------- quarantine

export type QuarantineState = 'pending' | 'stored' | 'restored' | 'deleted' | 'failed';

export interface QuarantineItem {
  id: string;
  threat_id: string | null;
  original_path: string;
  sha256: string;
  size: number;
  threat_name: string;
  severity: Severity;
  state: QuarantineState;
  quarantined_at: Timestamp;
  updated_at: Timestamp;
  note: string | null;
}

// ---------------------------------------------------------------- events

export const EVENT_CATEGORIES = [
  'scan',
  'threat',
  'quarantine',
  'real_time',
  'process',
  'persistence',
  'network',
  'domain',
  'usb',
  'ransomware',
  'memory',
  'behavior',
  'audit',
  'update',
  'policy',
  'system',
  'ai',
] as const;
export type EventCategory = (typeof EVENT_CATEGORIES)[number];

/** Arbitrary JSON value (serde_json::Value). */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface SecurityEvent {
  id: number;
  ts: Timestamp;
  category: EventCategory;
  severity: Severity;
  kind: string;
  title: string;
  message: string;
  data: JsonValue;
}

// ---------------------------------------------------------------- incidents

export const INCIDENT_KINDS = [
  'remote_access_trojan',
  'spyware',
  'ransomware',
  'persistence',
  'suspicious_script',
  'security_tampering',
  'memory_tampering',
  'adware',
  'network_threat',
  'generic',
] as const;
export type IncidentKind = (typeof INCIDENT_KINDS)[number];

export const INCIDENT_STATUSES = ['open', 'acknowledged', 'resolved', 'false_positive'] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export interface Evidence {
  event_id: number | null;
  indicator: string;
  weight: number;
  detail: string;
  ts: Timestamp;
}

export interface Incident {
  id: string;
  kind: IncidentKind;
  severity: Severity;
  /** 0..=100 */
  confidence: number;
  title: string;
  summary: string;
  process: ProcessInfo | null;
  evidence: Evidence[];
  status: IncidentStatus;
  created_at: Timestamp;
  updated_at: Timestamp;
}

// ---------------------------------------------------------------- processes

export type SignatureStatus = 'valid' | 'unsigned' | 'invalid' | 'untrusted' | 'unknown';

export interface SignatureInfo {
  status: SignatureStatus;
  publisher: string | null;
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  name: string;
  path: string | null;
  command_line: string | null;
  signature: SignatureInfo | null;
  parent_name: string | null;
  session_id: number | null;
  working_set_bytes: number | null;
  first_seen: Timestamp;
  flags: string[];
  critical: boolean;
}

// ---------------------------------------------------------------- network

export type Reputation = 'known_malicious' | 'suspicious' | 'unknown' | 'trusted';

export interface ConnectionInfo {
  protocol: string;
  local_addr: string;
  local_port: number;
  remote_addr: string | null;
  remote_port: number | null;
  state: string;
  pid: number;
  process_name: string | null;
  process_path: string | null;
  reputation: Reputation;
  reputation_reason: string | null;
  is_private_remote: boolean;
}

export type DomainList = 'allow' | 'block';

export interface DomainRule {
  domain: string;
  list: DomainList;
  added_at: Timestamp;
  note: string | null;
}

export interface DomainCheck {
  domain: string;
  reputation: Reputation;
  category: string | null;
  matched_rule: string | null;
  source: string | null;
}

export interface DomainListInfo {
  name: string;
  category: string;
  entries: number;
  source: string;
  license: string;
  enabled: boolean;
}

export interface DomainProtectionStatus {
  lists: DomainListInfo[];
  user_rules: DomainRule[];
  hosts_enforcement: ModuleState;
  hosts_enforcement_detail: string;
  enforced_domain_count: number;
  blocked_ips: string[];
  limitations: string[];
}

// ---------------------------------------------------------------- startup

export type StartupLocation =
  | 'registry_run'
  | 'registry_run_once'
  | 'startup_folder'
  | 'scheduled_task'
  | 'service'
  | 'winlogon';

export type Assessment = 'trusted' | 'unknown' | 'suspicious' | 'malicious';

export interface StartupItem {
  id: string;
  location: StartupLocation;
  /** `user` or `machine` */
  scope: string;
  container: string;
  name: string;
  command: string;
  executable_path: string | null;
  signature: SignatureInfo | null;
  modified_at: Timestamp | null;
  first_seen: Timestamp;
  assessment: Assessment;
  indicators: string[];
  can_disable: boolean;
  is_new: boolean;
}

export interface StartupBackup {
  id: string;
  item_name: string;
  container: string;
  value: string;
  created_at: Timestamp;
  restored: boolean;
}

// ---------------------------------------------------------------- usb

export interface UsbDrive {
  root: string;
  label: string | null;
  filesystem: string | null;
  total_bytes: number | null;
  free_bytes: number | null;
  inserted_at: Timestamp;
  autorun_inf: boolean;
  suspicious_items: string[];
  last_scan_job: string | null;
  accessible: boolean;
}

// ---------------------------------------------------------------- audit

export type AuditStatus =
  | 'pass'
  | 'warning'
  | 'fail'
  | 'unknown'
  | 'requires_elevation'
  | 'not_applicable';

export interface AuditCheck {
  id: string;
  category: string;
  title: string;
  status: AuditStatus;
  detail: string;
  recommendation: string | null;
  doc_url: string | null;
}

export interface AuditReport {
  generated_at: Timestamp;
  os_caption: string | null;
  os_build: string | null;
  elevated: boolean;
  checks: AuditCheck[];
}

export interface DefenderStatus {
  available: boolean;
  antivirus_enabled: boolean | null;
  real_time_protection: boolean | null;
  tamper_protection: boolean | null;
  signature_version: string | null;
  signature_age_days: number | null;
  detail: string;
}

// ---------------------------------------------------------------- ransomware / memory

export interface ProcessIoSample {
  pid: number;
  name: string;
  path: string | null;
  write_bytes_delta: number;
  write_ops_delta: number;
  allowlisted: boolean;
  critical: boolean;
}

export interface RansomwareSignal {
  ts: Timestamp;
  folder: string;
  modified: number;
  renamed: number;
  deleted: number;
  created: number;
  extension_changes: number;
  high_entropy_writes: number;
  ransom_note_names: string[];
  score: number;
  suspected_processes: ProcessIoSample[];
  event_id: number | null;
}

export interface RansomwareStatus {
  state: ModuleState;
  protected_folders: string[];
  monitored_folders: string[];
  window_secs: number;
  recent_bursts: RansomwareSignal[];
  allowlisted_processes: string[];
  backups_available: boolean;
  limitations: string[];
}

export interface MemoryOverview {
  state: ModuleState;
  detail: string;
  processes: ProcessInfo[];
  total_physical_bytes: number;
  available_physical_bytes: number;
  recent_events: SecurityEvent[];
  limitations: string[];
}

// ---------------------------------------------------------------- AI

export interface AiStatus {
  classifier_state: ModuleState;
  classifier_detail: string;
  model_version: string | null;
  model_decisions_enabled: boolean;
  analyst_state: ModuleState;
  analyst_detail: string;
  analyst_backend: string | null;
  analyst_model: string | null;
}

export interface SourceRef {
  /** `event`, `threat`, `incident`, `scan`, `quarantine`, `module`, `audit` */
  kind: string;
  id: string;
  label: string;
}

export interface AnalystAnswer {
  answer: string;
  sources: SourceRef[];
  /** `ollama:<model>` or `rule_based` */
  backend: string;
  grounded: boolean;
  warnings: string[];
}

// ---------------------------------------------------------------- updates

export interface RuleSetInfo {
  name: string;
  file: string;
  source: string;
  license: string;
  version: string;
  rule_count: number;
  compiled_ok: boolean;
  error: string | null;
}

export interface UpdateRecord {
  id: number;
  ts: Timestamp;
  component: string;
  from_version: string | null;
  to_version: string | null;
  success: boolean;
  message: string;
}

export interface UpdateStatus {
  rules_version: string;
  rules_loaded_at: Timestamp | null;
  rule_sets: RuleSetInfo[];
  hash_db_entries: number;
  clamav_state: ModuleState;
  clamav_detail: string;
  app_update_channel: string;
  trusted_key_fingerprints: string[];
  history: UpdateRecord[];
}

// ---------------------------------------------------------------- settings

export type AutoAction = 'notify_only' | 'quarantine_confirmed';

export type Cadence =
  | { type: 'daily'; hour: number; minute: number }
  | { type: 'weekly'; weekday: number; hour: number; minute: number };

export interface ScheduleEntry {
  id: string;
  kind: ScanKind;
  cadence: Cadence;
  enabled: boolean;
  last_run: Timestamp | null;
  catch_up: boolean;
}

export interface Settings {
  language: string;
  theme: string;
  realtime_enabled: boolean;
  realtime_paused_until: Timestamp | null;
  auto_action: AutoAction;
  scan_archives: boolean;
  max_archive_depth: number;
  max_archive_expanded_mb: number;
  max_file_size_mb: number;
  scan_threads: number;
  low_priority_scans: boolean;
  exclusions: string[];
  schedules: ScheduleEntry[];
  gaming_mode: boolean;
  gaming_mode_auto: boolean;
  usb_scan_on_insert: boolean;
  ransomware_enabled: boolean;
  protected_folders: string[];
  ransomware_allowlist: string[];
  process_monitor_enabled: boolean;
  network_monitor_enabled: boolean;
  hosts_blocking_enabled: boolean;
  ad_blocklist_enabled: boolean;
  clamav_enabled: boolean;
  clamav_path: string | null;
  analyst_enabled: boolean;
  analyst_endpoint: string;
  analyst_model: string;
  notifications_enabled: boolean;
  telemetry_enabled: boolean;
  event_retention_days: number;
}

// ---------------------------------------------------------------- dashboard / diagnostics

export interface ResourceUsage {
  service_cpu_percent: number | null;
  service_working_set_bytes: number | null;
  service_private_bytes: number | null;
  system_memory_load_percent: number | null;
  measured_at: Timestamp;
}

export type OverallProtection = 'protected' | 'reduced' | 'at_risk';

export interface DashboardSummary {
  overall: OverallProtection;
  service_mode: string;
  elevated: boolean;
  modules: ModuleStatus[];
  defender: DefenderStatus;
  last_scan: ScanJobSummary | null;
  active_scan: ScanProgress | null;
  active_threats: number;
  total_detections: number;
  quarantine_count: number;
  open_incidents: number;
  last_rules_update: Timestamp | null;
  rules_version: string;
  recent_events: SecurityEvent[];
  critical_alerts: SecurityEvent[];
  coverage_warnings: string[];
  resources: ResourceUsage;
  gaming_mode_active: boolean;
  realtime_paused_until: Timestamp | null;
}

export interface Diagnostics {
  version: string;
  protocol_version: number;
  service_mode: string;
  elevated: boolean;
  data_dir: string;
  quarantine_dir: string;
  rules_dir: string;
  log_dir: string;
  db_path: string;
  db_size_bytes: number;
  db_integrity_ok: boolean;
  os: string;
  uptime_secs: number;
  modules: ModuleStatus[];
  build_profile: string;
}

export interface DayStat {
  day: string;
  events: number;
  threats: number;
  scans: number;
}

export interface HistoryStats {
  days: DayStat[];
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
}

// ---------------------------------------------------------------- errors

export const ERROR_CODES = [
  'invalid_input',
  'not_found',
  'permission_denied',
  'unauthorized',
  'conflict',
  'unavailable',
  'busy',
  'timeout',
  'io',
  'database',
  'parse',
  'policy',
  'integrity',
  'internal',
  'not_connected',
] as const;
/** `ErrorCode` from error.rs plus the bridge-only `not_connected`. */
export type ErrorCode = (typeof ERROR_CODES)[number];

export interface IpcError {
  code: ErrorCode;
  message: string;
}

// ---------------------------------------------------------------- protocol

/**
 * Discriminated union mirroring `protocol::Request`
 * (`#[serde(tag = "cmd", content = "args", rename_all = "snake_case")]`).
 */
export type AegisRequest =
  | { cmd: 'ping' }
  | { cmd: 'get_dashboard' }
  | { cmd: 'get_modules' }
  | { cmd: 'get_diagnostics' }
  // scanning
  | { cmd: 'start_scan'; args: { kind: ScanKind; paths: string[] } }
  | { cmd: 'cancel_scan'; args: { job_id: string } }
  | { cmd: 'pause_scan'; args: { job_id: string } }
  | { cmd: 'resume_scan'; args: { job_id: string } }
  | { cmd: 'get_scan_progress'; args: { job_id: string | null } }
  | { cmd: 'list_scan_jobs'; args: { limit: number } }
  // threats & quarantine
  | { cmd: 'list_threats'; args: { status: ThreatStatus | null; limit: number } }
  | { cmd: 'threat_action'; args: { threat_id: string; action: ThreatAction } }
  | { cmd: 'list_quarantine' }
  | {
      cmd: 'restore_quarantine';
      args: { id: string; accept_risk: boolean; destination_dir: string | null };
    }
  | { cmd: 'delete_quarantine'; args: { id: string } }
  // events / incidents / history
  | {
      cmd: 'list_events';
      args: {
        category: EventCategory | null;
        min_severity: Severity | null;
        before_id: number | null;
        limit: number;
      };
    }
  | { cmd: 'list_incidents'; args: { status: IncidentStatus | null; limit: number } }
  | { cmd: 'update_incident'; args: { id: string; status: IncidentStatus } }
  | { cmd: 'get_history_stats'; args: { days: number } }
  | { cmd: 'export_report' }
  | { cmd: 'delete_history'; args: { older_than_days: number } }
  // settings & protection control
  | { cmd: 'get_settings' }
  | { cmd: 'update_settings'; args: { settings: Settings } }
  | { cmd: 'set_realtime'; args: { enabled: boolean; pause_minutes: number | null } }
  | { cmd: 'set_gaming_mode'; args: { enabled: boolean } }
  // processes / memory / ransomware
  | { cmd: 'list_processes' }
  | { cmd: 'get_memory_overview' }
  | { cmd: 'suspend_process'; args: { pid: number; incident_id: string | null; confirm: boolean } }
  | { cmd: 'resume_process'; args: { pid: number } }
  | { cmd: 'get_ransomware_status' }
  // network & domains
  | { cmd: 'list_connections' }
  | { cmd: 'get_domain_status' }
  | { cmd: 'check_domain'; args: { domain: string } }
  | { cmd: 'add_domain_rule'; args: { domain: string; list: DomainList; note: string | null } }
  | { cmd: 'remove_domain_rule'; args: { domain: string } }
  | { cmd: 'set_hosts_blocking'; args: { enabled: boolean } }
  | { cmd: 'block_ip'; args: { ip: string; confirm: boolean } }
  | { cmd: 'unblock_ip'; args: { ip: string } }
  // startup / usb / audit
  | { cmd: 'list_startup_items' }
  | { cmd: 'disable_startup_item'; args: { id: string; confirm: boolean } }
  | { cmd: 'list_startup_backups' }
  | { cmd: 'restore_startup_item'; args: { backup_id: string } }
  | { cmd: 'list_usb_drives' }
  | { cmd: 'scan_usb'; args: { root: string } }
  | { cmd: 'run_audit' }
  // AI
  | { cmd: 'get_ai_status' }
  | { cmd: 'ask_analyst'; args: { question: string; language: string } }
  // updates
  | { cmd: 'get_update_status' }
  | { cmd: 'reload_rules' }
  | { cmd: 'apply_rule_pack'; args: { path: string } }
  | { cmd: 'update_clamav_database' };

export type AegisCmd = AegisRequest['cmd'];

export interface SuspendResult {
  pid: number;
  suspended_threads: number;
}

/** Response `data` type for every command. */
export interface ResponseMap {
  ping: { pong: boolean; version: string };
  get_dashboard: DashboardSummary;
  get_modules: ModuleStatus[];
  get_diagnostics: Diagnostics;
  start_scan: ScanProgress;
  cancel_scan: ScanProgress;
  pause_scan: ScanProgress;
  resume_scan: ScanProgress;
  get_scan_progress: ScanProgress | null;
  list_scan_jobs: ScanJobSummary[];
  list_threats: ThreatRecord[];
  threat_action: ThreatRecord;
  list_quarantine: QuarantineItem[];
  restore_quarantine: QuarantineItem;
  delete_quarantine: QuarantineItem;
  list_events: SecurityEvent[];
  list_incidents: Incident[];
  update_incident: Incident;
  get_history_stats: HistoryStats;
  export_report: { path: string };
  delete_history: { deleted: number };
  get_settings: Settings;
  update_settings: Settings;
  set_realtime: Settings;
  set_gaming_mode: Settings;
  list_processes: ProcessInfo[];
  get_memory_overview: MemoryOverview;
  suspend_process: SuspendResult;
  resume_process: SuspendResult;
  get_ransomware_status: RansomwareStatus;
  list_connections: ConnectionInfo[];
  get_domain_status: DomainProtectionStatus;
  check_domain: DomainCheck;
  add_domain_rule: DomainProtectionStatus;
  remove_domain_rule: DomainProtectionStatus;
  set_hosts_blocking: DomainProtectionStatus;
  block_ip: DomainProtectionStatus;
  unblock_ip: DomainProtectionStatus;
  list_startup_items: StartupItem[];
  disable_startup_item: StartupBackup;
  list_startup_backups: StartupBackup[];
  restore_startup_item: StartupBackup;
  list_usb_drives: UsbDrive[];
  scan_usb: ScanProgress;
  run_audit: AuditReport;
  get_ai_status: AiStatus;
  ask_analyst: AnalystAnswer;
  get_update_status: UpdateStatus;
  reload_rules: UpdateStatus;
  apply_rule_pack: UpdateStatus;
  update_clamav_database: { message: string };
}

/** Compile-time check: every cmd has a response type and vice-versa. */
type _AssertAllCmdsMapped = [AegisCmd] extends [keyof ResponseMap]
  ? [keyof ResponseMap] extends [AegisCmd]
    ? true
    : never
  : never;
export const __cmdMapComplete: _AssertAllCmdsMapped = true;

export type ResponseFor<C extends AegisCmd> = ResponseMap[C];
export type RequestFor<C extends AegisCmd> = Extract<AegisRequest, { cmd: C }>;

// ---------------------------------------------------------------- bridge

export type ConnectionMode = 'service' | 'user';

export interface ConnectionStatus {
  connected: boolean;
  mode: ConnectionMode | null;
  pipe: string | null;
  privileged_allowed: boolean;
  service_version: string | null;
  error: string | null;
}
