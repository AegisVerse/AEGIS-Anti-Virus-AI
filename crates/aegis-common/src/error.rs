use serde::{Deserialize, Serialize};

/// Stable error codes exposed over IPC. The UI maps them to localized text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    NotFound,
    PermissionDenied,
    Unauthorized,
    Conflict,
    Unavailable,
    Busy,
    Timeout,
    Io,
    Database,
    Parse,
    Policy,
    Integrity,
    Internal,
}

#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("busy: {0}")]
    Busy(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("blocked by policy: {0}")]
    Policy(String),
    #[error("integrity check failed: {0}")]
    Integrity(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl AegisError {
    pub fn code(&self) -> ErrorCode {
        match self {
            AegisError::InvalidInput(_) => ErrorCode::InvalidInput,
            AegisError::NotFound(_) => ErrorCode::NotFound,
            AegisError::PermissionDenied(_) => ErrorCode::PermissionDenied,
            AegisError::Unauthorized(_) => ErrorCode::Unauthorized,
            AegisError::Conflict(_) => ErrorCode::Conflict,
            AegisError::Unavailable(_) => ErrorCode::Unavailable,
            AegisError::Busy(_) => ErrorCode::Busy,
            AegisError::Timeout(_) => ErrorCode::Timeout,
            AegisError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                ErrorCode::PermissionDenied
            }
            AegisError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => ErrorCode::NotFound,
            AegisError::Io(_) => ErrorCode::Io,
            AegisError::Database(_) => ErrorCode::Database,
            AegisError::Parse(_) => ErrorCode::Parse,
            AegisError::Policy(_) => ErrorCode::Policy,
            AegisError::Integrity(_) => ErrorCode::Integrity,
            AegisError::Internal(_) => ErrorCode::Internal,
        }
    }
}

impl From<serde_json::Error> for AegisError {
    fn from(e: serde_json::Error) -> Self {
        AegisError::Parse(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AegisError>;

