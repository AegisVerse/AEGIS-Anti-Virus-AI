//! Real-time filesystem watcher and process monitoring subsystem.

pub mod filesystem;
pub mod process;

pub use filesystem::RealTimeWatcher;
pub use process::ProcessMonitor;

