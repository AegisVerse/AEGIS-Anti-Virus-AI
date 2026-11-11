//! Shared types for AEGIS AI Security.
//!
//! This crate defines the data model and the IPC protocol shared by the
//! privileged security service, the Tauri desktop bridge and the tests.
//! It deliberately contains no privileged operations.

pub mod error;
pub mod hash;
pub mod paths;
pub mod protocol;
pub mod types;
pub mod validate;

pub use error::{AegisError, Result};
pub use types::*;

/// Product version, kept in sync with the workspace version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Human readable product name.
pub const PRODUCT_NAME: &str = "AEGIS AI Security";
/// IPC protocol version. Bump on incompatible protocol changes.
pub const PROTOCOL_VERSION: u32 = 1;

