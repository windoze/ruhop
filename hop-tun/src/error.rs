//! Error types for hop-tun

use std::io;
use thiserror::Error;

/// Result type alias for hop-tun operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during TUN device operations
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error from underlying system calls
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Device creation error
    #[error("device creation error: {0}")]
    DeviceCreation(String),

    /// Device not found
    #[error("device not found: {0}")]
    DeviceNotFound(String),

    /// Permission denied
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Route management error
    #[error("route error: {0}")]
    Route(String),

    /// NAT/Masquerading error
    #[error("NAT error: {0}")]
    Nat(String),

    /// Invalid IP address
    #[error("invalid IP address: {0}")]
    InvalidAddress(String),

    /// Invalid network prefix
    #[error("invalid network prefix: {0}")]
    InvalidPrefix(String),

    /// Operation not supported on this platform
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// Device is already up/configured
    #[error("device already exists: {0}")]
    AlreadyExists(String),

    /// Timeout error
    #[error("operation timed out: {0}")]
    Timeout(String),

    /// Internal error from underlying TUN library
    #[error("TUN library error: {0}")]
    TunLib(String),
}

impl Error {
    /// Check if the error is a permission-related error
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Error::PermissionDenied(_))
            || matches!(self, Error::Io(e) if e.kind() == io::ErrorKind::PermissionDenied)
    }

    /// Check if the error is a not-found error
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::DeviceNotFound(_))
            || matches!(self, Error::Io(e) if e.kind() == io::ErrorKind::NotFound)
    }
}
