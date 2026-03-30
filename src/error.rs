use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoreError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("order keys are not strictly increasing")]
    InvalidOrderRange,
    #[error("block not found: {0}")]
    BlockNotFound(String),
    #[error("permission denied")]
    PermissionDenied,
    #[error("external service error: {0}")]
    ExternalService(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, LoreError>;
