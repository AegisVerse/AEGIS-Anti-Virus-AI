//! Domain and IP intelligence, blocklist querying, and Windows hosts/firewall enforcement.

use aegis_common::error::{AegisError, Result};
use aegis_common::types::*;
use aegis_common::validate::{normalize_domain, validate_block_ip};
use aegis_storage::Storage;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const SEED_MALWARE_DOMAINS: &str = include_str!("../../../rules/domains/malware.txt");
pub const SEED_PHISHING_DOMAINS: &str = include_str!("../../../rules/domains/phishing.txt");
pub const SEED_ADS_DOMAINS: &str = include_str!("../../../rules/domains/ads_trackers.txt");

pub struct DomainShield {
    storage: Arc<Storage>,
    malware_domains: RwLock<HashSet<String>>,
    phishing_domains: RwLock<HashSet<String>>,
    ad_domains: RwLock<HashSet<String>>,
    rules_dir: Option<PathBuf>,
}

impl DomainShield {
    pub fn new(storage: Arc<Storage>, rules_dir: Option<PathBuf>) -> Self {
        let mut shield = Self {
            storage,
            malware_domains: RwLock::new(HashSet::new()),
            phishing_domains: RwLock::new(HashSet::new()),
            ad_domains: RwLock::new(HashSet::new()),
            rules_dir,
        };
        shield.load_seed_lists();
        shield
    }

    fn load_seed_lists(&self) {
        Self::parse_into_set(SEED_MALWARE_DOMAINS, &mut self.malware_domains.write());
        Self::parse_into_set(SEED_PHISHING_DOMAINS, &mut self.phishing_domains.write());
        Self::parse_into_set(SEED_ADS_DOMAINS, &mut self.ad_domains.write());
    }

    fn parse_into_set(raw: &str, set: &mut HashSet<String>) {
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Ok(d) = normalize_domain(trimmed) {
                set.insert(d);
            }
        }
    }

    /// Check a domain's reputation against user rules and active blocklists.
    pub fn check_domain(&self, domain_raw: &str) -> DomainCheck {
        let normalized = match normalize_domain(domain_raw) {
            Ok(d) => d,
            Err(_) => {
                return DomainCheck {
                    domain: domain_raw.to_string(),
                    reputation: Reputation::Unknown,
                    category: None,
                    matched_rule: None,
                    source: None,
                };
            }
        };

        // 1. User rules from storage (Allow takes precedence)
        if let Ok(rules) = self.storage.list_domain_rules() {
            for r in rules {
                if r.domain == normalized {
                    if r.list == DomainList::Allow {
                        return DomainCheck {
                            domain: normalized,
                            reputation: Reputation::Trusted,
                            category: Some("User Allowlist".into()),
                            matched_rule: Some(r.domain),
                            source: Some("user_rule".into()),
                        };
                    } else {
                        return DomainCheck {
                            domain: normalized,
                            reputation: Reputation::KnownMalicious,
                            category: Some("User Blocklist".into()),
                            matched_rule: Some(r.domain),
                            source: Some("user_rule".into()),
                        };
                    }
                }
            }
        }

        // 2. Malware domains
        if self.malware_domains.read().contains(&normalized) {
            return DomainCheck {
                domain: normalized,
                reputation: Reputation::KnownMalicious,
                category: Some("Malware / C2".into()),
                matched_rule: Some("seed.malware".into()),
                source: Some("AEGIS Curated Threat Intelligence".into()),
            };
        }

        // 3. Phishing domains
        if self.phishing_domains.read().contains(&normalized) {
            return DomainCheck {
                domain: normalized,
                reputation: Reputation::KnownMalicious,
                category: Some("Phishing & Deceptive".into()),
                matched_rule: Some("seed.phishing".into()),
                source: Some("AEGIS Phishing Intelligence".into()),
            };
        }

        // 4. Advertising & Trackers
        if self.ad_domains.read().contains(&normalized) {
            return DomainCheck {
                domain: normalized,
                reputation: Reputation::Suspicious,
                category: Some("Advertising & Telemetry".into()),
                matched_rule: Some("seed.ads_trackers".into()),
                source: Some("AEGIS Ad Shield".into()),
            };
        }

        DomainCheck {
            domain: normalized,
            reputation: Reputation::Unknown,
            category: None,
            matched_rule: None,
            source: None,
        }
    }

    /// Add a user domain allow/block rule.
    pub fn add_rule(&self, domain_raw: &str, list: DomainList, note: Option<&str>) -> Result<()> {
        let domain = normalize_domain(domain_raw)?;
        let rule = DomainRule {
            domain,
            list,
            added_at: Utc::now(),
            note: note.map(str::to_string),
        };
        self.storage.add_domain_rule(&rule)?;
        Ok(())
    }

    /// Remove a user domain rule.
    pub fn remove_rule(&self, domain_raw: &str) -> Result<bool> {
        let domain = normalize_domain(domain_raw)?;
        self.storage.remove_domain_rule(&domain)
    }

    /// Block an IP via Windows Firewall (using netsh if running elevated).
    pub fn block_ip(&self, ip_str: &str, confirm: bool) -> Result<()> {
        if !confirm {
            return Err(AegisError::Policy("Explicit confirmation required to block IP".into()));
        }
        let ip = validate_block_ip(ip_str)?;
        let rule_name = format!("AEGIS_Block_{}", ip);

        #[cfg(windows)]
        {
            let _ = std::process::Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule", &format!("name={}", rule_name), "dir=out", "action=block", &format!("remoteip={}", ip)])
                .output();
        }

        self.storage.add_blocked_ip(&ip.to_string(), &rule_name)?;
        Ok(())
    }

    /// Unblock an IP by removing firewall rule.
    pub fn unblock_ip(&self, ip_str: &str) -> Result<()> {
        let rule_name = self.storage.remove_blocked_ip(ip_str)?;
        if let Some(rname) = rule_name {
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("netsh")
                    .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rname)])
                    .output();
            }
        }
        Ok(())
    }

    pub fn get_status(&self) -> DomainProtectionStatus {
        let user_rules = self.storage.list_domain_rules().unwrap_or_default();
        let blocked_ips = self.storage.list_blocked_ips().unwrap_or_default();

        let lists = vec![
            DomainListInfo {
                name: "Malware & C2 Blocklist".into(),
                category: "Malware".into(),
                entries: self.malware_domains.read().len() as u64,
                source: "AEGIS Curated Intelligence".into(),
                license: "Apache-2.0".into(),
                enabled: true,
            },
            DomainListInfo {
                name: "Phishing Blocklist".into(),
                category: "Phishing".into(),
                entries: self.phishing_domains.read().len() as u64,
                source: "AEGIS Curated Intelligence".into(),
                license: "Apache-2.0".into(),
                enabled: true,
            },
            DomainListInfo {
                name: "Ad & Tracker Blocklist".into(),
                category: "Ads & Telemetry".into(),
                entries: self.ad_domains.read().len() as u64,
                source: "AEGIS Curated Intelligence".into(),
                license: "Apache-2.0".into(),
                enabled: false,
            },
        ];

        DomainProtectionStatus {
            lists,
            user_rules,
            hosts_enforcement: ModuleState::Disabled,
            hosts_enforcement_detail: "Hosts-file redirect is optional and disabled by default".into(),
            enforced_domain_count: 0,
            blocked_ips,
            limitations: vec![
                "Encrypted DNS (DNS-over-HTTPS / DoH) and browser-internal resolvers bypass system DNS checks.".into(),
                "Use the companion AEGIS Web Shield browser extension for comprehensive in-browser blocking.".into(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_reputation_lookup() {
        let storage = Arc::new(Storage::open_in_memory().unwrap());
        let shield = DomainShield::new(storage, None);

        let check1 = shield.check_domain("aegis-test-malware.invalid");
        assert_eq!(check1.reputation, Reputation::KnownMalicious);

        let check2 = shield.check_domain("doubleclick.net");
        assert_eq!(check2.reputation, Reputation::Suspicious);

        let check3 = shield.check_domain("google.com");
        assert_eq!(check3.reputation, Reputation::Unknown);
    }
}

