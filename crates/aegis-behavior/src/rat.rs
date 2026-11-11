//! RAT and Trojan detection via process relationship and script execution heuristics.

use aegis_common::types::*;
use aegis_storage::Storage;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

pub struct RatHunter {
    storage: Arc<Storage>,
}

impl RatHunter {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    /// Analyze a newly observed or running process for RAT / Trojan execution patterns.
    pub fn analyze_process(&self, process: &ProcessInfo) -> Option<Incident> {
        let mut evidence = Vec::new();
        let mut incident_kind = IncidentKind::RemoteAccessTrojan;
        let mut title = String::new();
        let mut summary = String::new();

        let proc_name = process.name.to_ascii_lowercase();
        let parent_name = process.parent_name.as_deref().unwrap_or("").to_ascii_lowercase();
        let cmdline = process.command_line.as_deref().unwrap_or("").to_ascii_lowercase();

        // 1. Office / Browser spawning shell / scripting host
        let office_or_browser_parents = [
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "acrord32.exe", "acrobat.exe", "chrome.exe", "msedge.exe", "firefox.exe",
        ];
        let shell_children = [
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe",
        ];

        let parent_is_doc_or_web = office_or_browser_parents.iter().any(|&p| parent_name == p);
        let child_is_shell = shell_children.iter().any(|&c| proc_name == c);

        if parent_is_doc_or_web && child_is_shell {
            evidence.push(Evidence {
                event_id: None,
                indicator: "process.anomalous_parent".into(),
                weight: 40,
                detail: format!("Productivity/browser application '{}' spawned script/shell binary '{}'", parent_name, proc_name),
                ts: Utc::now(),
            });
            title = format!("Suspicious Process Lineage: {} -> {}", parent_name, proc_name);
            summary = "An application spawned a script or shell interpreter, a pattern frequently observed in spearphishing and malicious document attacks.".into();
            incident_kind = IncidentKind::RemoteAccessTrojan;
        }

        // 2. Suspicious PowerShell encoded command or hidden window
        if proc_name == "powershell.exe" || proc_name == "pwsh.exe" {
            let has_enc = cmdline.contains("-e ") || cmdline.contains("-enc ") || cmdline.contains("-encodedcommand");
            let has_hidden = cmdline.contains("-w hidden") || cmdline.contains("-windowstyle hidden");
            let has_cradle = cmdline.contains("downloadstring") || cmdline.contains("downloaddata") || cmdline.contains("invoke-webrequest") || cmdline.contains("iex");

            if has_enc && has_hidden {
                evidence.push(Evidence {
                    event_id: None,
                    indicator: "script.encoded_hidden_powershell".into(),
                    weight: 45,
                    detail: "PowerShell executed with both hidden window and encoded command arguments".into(),
                    ts: Utc::now(),
                });
            }

            if has_cradle {
                evidence.push(Evidence {
                    event_id: None,
                    indicator: "script.download_cradle".into(),
                    weight: 35,
                    detail: "PowerShell command contains in-memory download cradle indicators".into(),
                    ts: Utc::now(),
                });
            }
        }

        // 3. Credential dumping tool indicators in process commandline
        if cmdline.contains("sekurlsa") || cmdline.contains("lsadump") || cmdline.contains("mimikatz") {
            evidence.push(Evidence {
                event_id: None,
                indicator: "hacktool.credential_dumping".into(),
                weight: 50,
                detail: "Commandline contains explicit credential dumper keywords".into(),
                ts: Utc::now(),
            });
            incident_kind = IncidentKind::Spyware;
            title = "Potential Credential Dumping Activity".into();
            summary = "Activity matching credential access and harvesting utilities was observed.".into();
        }

        // 4. Recovery tampering (VSSAdmin / BCDEdit / WBAdmin)
        if (proc_name == "vssadmin.exe" && cmdline.contains("delete shadows"))
            || (proc_name == "bcdedit.exe" && cmdline.contains("recoveryenabled no"))
            || (proc_name == "wbadmin.exe" && cmdline.contains("delete catalog"))
        {
            evidence.push(Evidence {
                event_id: None,
                indicator: "system.shadow_copy_deletion".into(),
                weight: 50,
                detail: format!("Process '{}' executed commands to inhibit system recovery", proc_name),
                ts: Utc::now(),
            });
            incident_kind = IncidentKind::Ransomware;
            title = "System Backup Invalidation Attempt".into();
            summary = "System backup / shadow copy deletion was attempted, characteristic of pre-encryption ransomware steps.".into();
        }

        if evidence.is_empty() {
            return None;
        }

        let total_weight: u32 = evidence.iter().map(|e| e.weight as u32).sum();
        let confidence = (total_weight.min(100)) as u8;

        let severity = if confidence >= 80 {
            Severity::Critical
        } else if confidence >= 50 {
            Severity::High
        } else {
            Severity::Medium
        };

        if title.is_empty() {
            title = format!("Suspicious Activity: {}", process.name);
            summary = "Correlated anomalous behaviors detected from process telemetry.".into();
        }

        let incident = Incident {
            id: Uuid::new_v4().to_string(),
            kind: incident_kind,
            severity,
            confidence,
            title,
            summary,
            process: Some(process.clone()),
            evidence,
            status: IncidentStatus::Open,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let _ = self.storage.upsert_incident(&incident);

        let _ = self.storage.insert_event(&NewEvent::new(
            EventCategory::Behavior,
            severity,
            "incident.created",
            format!("Security Incident: {}", incident.title),
            format!("PID {}: {}", process.pid, incident.summary),
        ));

        Some(incident)
    }
}

