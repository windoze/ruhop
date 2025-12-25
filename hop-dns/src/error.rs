//! Error types for DNS operations

use thiserror::Error;

/// Result type alias for DNS operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during DNS operations
#[derive(Debug, Error)]
pub enum Error {
    /// DNS query/response error
    #[error("DNS error: {0}")]
    Dns(String),

    /// DNS configuration error
    #[error("DNS configuration error: {0}")]
    Config(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
