//! Shared errors from token processing, JSON serialization, and NKey operations.

/// Library result type using [`NjError`] for failures.
pub type Result<T> = std::result::Result<T, NjError>;

/// Token, JSON, or NKey failure returned by this library.
#[derive(Debug, thiserror::Error)]
pub enum NjError {
    /// Malformed, unsupported, or semantically rejected token data.
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// JSON encoding or decoding failure.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Key parsing, signing, or verification failure represented as a message.
    #[error("nkeys error: {0}")]
    Nkeys(String),
}
