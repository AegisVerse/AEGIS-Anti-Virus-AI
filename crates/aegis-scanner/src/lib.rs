//! Robust file scanner subsystem with multi-engine evaluation, archive inspection,
//! progress event stream, and cancellation support.

pub mod archive;
pub mod engine;
pub mod enumerator;

pub use engine::ScannerEngine;

