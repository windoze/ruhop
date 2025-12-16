//! Error types for the VPN engine

use thiserror::Error;

/// Result type alias for VPN operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during VPN operations
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Failed to parse configuration file
    #[error("failed to parse config: {0}")]
    ConfigParse(#[from] toml::de::Error),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol error
    #[error("protocol error: {0}")]
    Protocol(#[from] hop_protocol::Error),

    /// TUN device error
    #[error("TUN error: {0}")]
    Tun(#[from] hop_tun::Error),

    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// Authentication error
    #[error("authentication error: {0}")]
    Auth(String),

    /// Timeout error
    #[error("timeout: {0}")]
    Timeout(String),

    /// Session error
    #[error("session error: {0}")]
    Session(String),

    /// Already running
    #[error("VPN is already running")]
    AlreadyRunning,

    /// Not running
    #[error("VPN is not running")]
    NotRunning,

    /// Shutdown requested
    #[error("shutdown requested")]
    Shutdown,

    /// Invalid state
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Address allocation failed
    #[error("address allocation failed: {0}")]
    AddressAllocation(String),

    /// Script execution error
    #[error("script error: {0}")]
    Script(String),
}

impl Error {
    /// Check if this is a recoverable error
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::Timeout(_) | Error::Connection(_) | Error::Session(_)
        )
    }

    /// Check if this is a configuration error
    pub fn is_config_error(&self) -> bool {
        matches!(self, Error::Config(_) | Error::ConfigParse(_))
    }
}
