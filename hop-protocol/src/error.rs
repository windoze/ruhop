//! Error types for the hop protocol

use thiserror::Error;

/// Result type alias for hop protocol operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during protocol operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("invalid packet data")]
    InvalidPacket,

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("compression error: {0}")]
    Compression(String),

    #[error("decompression error: {0}")]
    Decompression(String),

    #[error("invalid padding")]
    InvalidPadding,

    #[error("fragment error: {0}")]
    Fragment(String),

    #[error("invalid session state transition from {from:?} to {to:?}")]
    InvalidStateTransition {
        from: crate::SessionState,
        to: crate::SessionState,
    },

    #[error("handshake error: {0}")]
    Handshake(String),

    #[error("address pool error: {0}")]
    Pool(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
