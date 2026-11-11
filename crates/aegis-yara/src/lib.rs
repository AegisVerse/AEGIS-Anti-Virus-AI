//! YARA-X integration for AEGIS AI Security.
//!
//! Compiles curated `.yar` / `.yara` files with the official `yara-x` crate,
//! embedded fallback rules, syntax validation, and metadata extraction.

use aegis_common::types::{Detection, DetectionSource, ModuleState, RuleSetInfo, Severity, Timestamp};
use aegis_common::{AegisError, Result};
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use yara_x::{Compiler, Rules, Scanner};

/// Embedded seed rules so scanning works even before external rule packs exist.
pub const EMBEDDED_TEST_RULES: &str = include_str!("../../../rules/yara/00_test_fixtures.yar");
pub const EMBEDDED_WINDOWS_RULES: &str = include_str!("../../../rules/yara/10_windows_indicators.yar");

struct CompiledSet {
    rules: Arc<Rules>,
    sets: Vec<RuleSetInfo>,
    version: String,
    loaded_at: Timestamp,
    total_rules: u64,
}

pub struct YaraEngine {
    inner: RwLock<CompiledSet>,
    rules_dir: Option<PathBuf>,
}

impl YaraEngine {
    /// Load rules from `rules_dir` (seeding default `.yar` files if the
    /// directory is empty), falling back to embedded rules on error.
    pub fn new(rules_dir: Option<PathBuf>) -> Result<Self> {
        if let Some(dir) = &rules_dir {
            let _ = std::fs::create_dir_all(dir);
            seed_default_rules(dir);
        }
        let compiled = Self::compile_from_dir(rules_dir.as_deref())?;
        Ok(Self { inner: RwLock::new(compiled), rules_dir })
    }

    /// Create an engine backed only by embedded rules (used in unit tests).
    pub fn embedded_only() -> Result<Self> {
        let compiled = Self::compile_sources(&[
            ("00_test_fixtures.yar".into(), EMBEDDED_TEST_RULES.into()),
            ("10_windows_indicators.yar".into(), EMBEDDED_WINDOWS_RULES.into()),
        ])?;
        Ok(Self { inner: RwLock::new(compiled), rules_dir: None })
    }

    /// Validate that a set of `.yar` files compiles cleanly without activating it.
    pub fn validate_directory(dir: &Path) -> Result<Vec<RuleSetInfo>> {
        let sources = read_yar_files(dir)?;
        if sources.is_empty() {
            return Err(AegisError::InvalidInput("no .yar/.yara files found in directory".into()));
        }
        let compiled = Self::compile_sources(&sources)?;
        if compiled.sets.iter().any(|s| !s.compiled_ok) || compiled.total_rules == 0 {
            return Err(AegisError::InvalidInput("one or more YARA rule files failed to compile".into()));
        }
        Ok(compiled.sets)
    }

    /// Reload rules from the configured directory. Keeps the previous working
    /// rules if the new ones fail to compile completely.
    pub fn reload(&self) -> Result<Vec<RuleSetInfo>> {
        let next = Self::compile_from_dir(self.rules_dir.as_deref())?;
        if next.total_rules == 0 {
            return Err(AegisError::Integrity("refusing to activate empty YARA rule set".into()));
        }
        let sets = next.sets.clone();
        *self.inner.write() = next;
        Ok(sets)
    }

    pub fn status(&self) -> (ModuleState, String, String, Timestamp, Vec<RuleSetInfo>) {
        let g = self.inner.read();
        let failed = g.sets.iter().filter(|s| !s.compiled_ok).count();
        let state = if g.total_rules == 0 {
            ModuleState::Error
        } else {
            ModuleState::Active
        };
        let detail = if failed > 0 {
            format!("{} active rules across {} sets ({failed} set failed compilation)", g.total_rules, g.sets.len())
        } else {
            format!("{} active rules across {} sets (v{})", g.total_rules, g.sets.len(), g.version)
        };
        (state, detail, g.version.clone(), g.loaded_at, g.sets.clone())
    }

    pub fn version(&self) -> String {
        self.inner.read().version.clone()
    }

    /// Scan an in-memory buffer with a per-scan timeout.
    pub fn scan_bytes(&self, data: &[u8], timeout: Duration) -> Result<Vec<Detection>> {
        let rules = self.inner.read().rules.clone();
        let mut scanner = Scanner::new(&rules);
        scanner.set_timeout(timeout);
        let results = scanner.scan(data).map_err(|e| AegisError::Internal(format!("yara scan: {e}")))?;
        Ok(collect_matches(&results))
    }

    /// Scan a file path with a per-scan timeout.
    pub fn scan_file(&self, path: &Path, timeout: Duration) -> Result<Vec<Detection>> {
        let rules = self.inner.read().rules.clone();
        let mut scanner = Scanner::new(&rules);
        scanner.set_timeout(timeout);
        let results = scanner.scan_file(path).map_err(|e| AegisError::Internal(format!("yara scan_file: {e}")))?;
        Ok(collect_matches(&results))
    }

    fn compile_from_dir(dir: Option<&Path>) -> Result<CompiledSet> {
        let mut sources = match dir {
            Some(d) if d.exists() => read_yar_files(d).unwrap_or_default(),
            _ => Vec::new(),
        };
        if sources.is_empty() {
            sources = vec![
                ("00_test_fixtures.yar".into(), EMBEDDED_TEST_RULES.into()),
                ("10_windows_indicators.yar".into(), EMBEDDED_WINDOWS_RULES.into()),
            ];
        }
        Self::compile_sources(&sources)
    }

    fn compile_sources(sources: &[(String, String)]) -> Result<CompiledSet> {
        let mut compiler = Compiler::new();
        let mut sets = Vec::new();
        let mut latest_version = String::from("2026.11.1");

        for (file, content) in sources {
            let header = parse_header_comments(content);
            let approx_rules = count_rules_in_source(content);
            // Validate each file in its own compiler first so a single broken
            // file is reported cleanly without poisoning the working sets.
            let mut single = Compiler::new();
            match single.add_source(content.as_str()) {
                Ok(_) => {
                    let _ = compiler.add_source(content.as_str());
                    if let Some(v) = header.get("version") {
                        latest_version = v.clone();
                    }
                    sets.push(RuleSetInfo {
                        name: header.get("name").cloned().unwrap_or_else(|| file.clone()),
                        file: file.clone(),
                        source: header.get("source").cloned().unwrap_or_else(|| "local".into()),
                        license: header.get("license").cloned().unwrap_or_else(|| "Apache-2.0".into()),
                        version: header.get("version").cloned().unwrap_or_else(|| "2026.11.1".into()),
                        rule_count: approx_rules,
                        compiled_ok: true,
                        error: None,
                    });
                }
                Err(err) => {
                    tracing::warn!("YARA rule file {file} failed to compile: {err}");
                    sets.push(RuleSetInfo {
                        name: file.clone(),
                        file: file.clone(),
                        source: header.get("source").cloned().unwrap_or_else(|| "local".into()),
                        license: header.get("license").cloned().unwrap_or_else(|| "unknown".into()),
                        version: header.get("version").cloned().unwrap_or_else(|| "unknown".into()),
                        rule_count: 0,
                        compiled_ok: false,
                        error: Some(err.to_string()),
                    });
                }
            }
        }

        let rules = compiler.build();
        let total_rules = rules.iter().count() as u64;
        Ok(CompiledSet {
            rules: Arc::new(rules),
            sets,
            version: latest_version,
            loaded_at: Utc::now(),
            total_rules,
        })
    }
}

fn collect_matches(results: &yara_x::ScanResults<'_, '_>) -> Vec<Detection> {
    let mut out = Vec::new();
    for rule in results.matching_rules() {
        let id = rule.identifier().to_string();
        let mut meta = BTreeMap::new();
        for (k, v) in rule.metadata() {
            let val = match v {
                yara_x::MetaValue::Integer(i) => i.to_string(),
                yara_x::MetaValue::Float(f) => f.to_string(),
                yara_x::MetaValue::Bool(b) => b.to_string(),
                yara_x::MetaValue::String(s) => s.to_string(),
                yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            };
            meta.insert(k.to_string(), val);
        }
        let severity = meta
            .get("severity")
            .and_then(|s| Severity::parse(s))
            .unwrap_or(Severity::High);
        let confidence = meta
            .get("confidence")
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(85)
            .clamp(1, 100);
        let name = meta.get("family").cloned().unwrap_or_else(|| id.clone());
        let description = meta
            .get("description")
            .cloned()
            .unwrap_or_else(|| format!("Matched YARA rule {id}"));
        out.push(Detection {
            source: DetectionSource::Yara,
            rule_id: format!("yara:{id}"),
            name,
            severity,
            confidence,
            description,
            metadata: meta,
        });
    }
    out
}

fn seed_default_rules(dir: &Path) {
    let f0 = dir.join("00_test_fixtures.yar");
    let f1 = dir.join("10_windows_indicators.yar");
    if !f0.exists() {
        let _ = std::fs::write(&f0, EMBEDDED_TEST_RULES);
    }
    if !f1.exists() {
        let _ = std::fs::write(&f1, EMBEDDED_WINDOWS_RULES);
    }
}

fn read_yar_files(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && matches!(
                    p.extension().and_then(|s| s.to_str()).map(|s| s.to_ascii_lowercase()).as_deref(),
                    Some("yar" | "yara")
                )
        })
        .collect();
    entries.sort();
    let mut out = Vec::new();
    for p in entries {
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("rules.yar").to_string();
        let content = std::fs::read_to_string(&p)?;
        out.push((name, content));
    }
    Ok(out)
}

fn parse_header_comments(src: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in src.lines().take(20) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("//") {
            if let Some((k, v)) = rest.split_once(':') {
                m.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
    }
    m
}

fn count_rules_in_source(src: &str) -> u64 {
    src.lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("rule ") || t.starts_with("private rule ") || t.starts_with("global rule ")
        })
        .count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_harmless_test_fixture_and_ignores_clean() {
        let eng = YaraEngine::embedded_only().unwrap();
        let clean = eng.scan_bytes(b"normal harmless text document", Duration::from_secs(5)).unwrap();
        assert!(clean.is_empty());

        let payload = b"header AEGIS-HARMLESS-TEST-SIGNATURE-2026-DO-NOT-EXECUTE footer";
        let hits = eng.scan_bytes(payload, Duration::from_secs(5)).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "yara:AEGIS_Test_Signature");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].confidence, 100);
    }

    #[test]
    fn isolates_broken_rule_file_without_losing_valid_rules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("00_test_fixtures.yar"), EMBEDDED_TEST_RULES).unwrap();
        std::fs::write(dir.path().join("99_broken.yar"), "rule Broken { condition: this_is_not_valid }").unwrap();
        let eng = YaraEngine::new(Some(dir.path().to_path_buf())).unwrap();
        let (state, _, _, _, sets) = eng.status();
        assert_eq!(state, ModuleState::Active);
        assert!(sets.iter().any(|s| s.file == "99_broken.yar" && !s.compiled_ok && s.error.is_some()));
        // Valid rules still match:
        let hits = eng
            .scan_bytes(b"AEGIS-HARMLESS-TEST-SIGNATURE-2026-DO-NOT-EXECUTE", Duration::from_secs(5))
            .unwrap();
        assert_eq!(hits.len(), 1);
        // And directory validation rejects the folder with the broken file:
        assert!(YaraEngine::validate_directory(dir.path()).is_err());
    }
}

