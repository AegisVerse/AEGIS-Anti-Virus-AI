//! Behavior analysis, RAT detection, and ransomware shield for AEGIS AI Security.
//!
//! Evaluates behavioral indicators:
//! - Suspicious parent-child process chains (e.g. Office or browser spawning PowerShell/CMD).
//! - Encoded scripts and obfuscated download cradles.
//! - Ransomware bursts: rapid file modification/rename frequency, mass extension changes,
//!   and ransom note generation.
//! - Correlates indicators into structured `Incident` records with evidence and confidence.

pub mod rat;
pub mod ransomware;

pub use rat::RatHunter;
pub use ransomware::RansomwareShield;

