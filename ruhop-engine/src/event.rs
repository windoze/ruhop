//! VPN events and state management

use std::net::IpAddr;
use std::time::{Duration, Instant};

/// VPN connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    /// VPN is not running
    Disconnected,
    /// Connecting to server (client) or starting up (server)
    Connecting,
    /// Performing handshake
    Handshaking,
    /// Connected and operational
    Connected,
    /// Reconnecting after a connection loss
    Reconnecting,
    /// Disconnecting gracefully
    Disconnecting,
    /// Error state
    Error,
}

impl VpnState {
    /// Check if the VPN is in an active state
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            VpnState::Connecting
                | VpnState::Handshaking
                | VpnState::Connected
                | VpnState::Reconnecting
        )
    }

    /// Check if the VPN is fully connected
    pub fn is_connected(&self) -> bool {
        matches!(self, VpnState::Connected)
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            VpnState::Disconnected => "Disconnected",
            VpnState::Connecting => "Connecting...",
            VpnState::Handshaking => "Handshaking...",
            VpnState::Connected => "Connected",
            VpnState::Reconnecting => "Reconnecting...",
            VpnState::Disconnecting => "Disconnecting...",
            VpnState::Error => "Error",
        }
    }
}

impl std::fmt::Display for VpnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Statistics about the VPN connection
#[derive(Debug, Clone, Default)]
pub struct VpnStats {
    /// Bytes received through the tunnel
    pub bytes_rx: u64,
    /// Bytes transmitted through the tunnel
    pub bytes_tx: u64,
    /// Packets received
    pub packets_rx: u64,
    /// Packets transmitted
    pub packets_tx: u64,
    /// Connection uptime
    pub uptime: Duration,
    /// Number of active sessions (server only)
    pub active_sessions: usize,
    /// Last packet received time
    pub last_rx: Option<Instant>,
    /// Last packet transmitted time
    pub last_tx: Option<Instant>,
}

impl VpnStats {
    /// Create new stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Update with received bytes
    pub fn record_rx(&mut self, bytes: usize) {
        self.bytes_rx += bytes as u64;
        self.packets_rx += 1;
        self.last_rx = Some(Instant::now());
    }

    /// Update with transmitted bytes
    pub fn record_tx(&mut self, bytes: usize) {
        self.bytes_tx += bytes as u64;
        self.packets_tx += 1;
        self.last_tx = Some(Instant::now());
    }

    /// Get the total bytes transferred
    pub fn total_bytes(&self) -> u64 {
        self.bytes_rx + self.bytes_tx
    }
}

/// Events emitted by the VPN engine
#[derive(Debug, Clone)]
pub enum VpnEvent {
    /// State changed
    StateChanged {
        old: VpnState,
        new: VpnState,
    },

    /// Connected to server (client) or client connected (server)
    Connected {
        /// Assigned tunnel IP address
        tunnel_ip: IpAddr,
        /// Server/peer IP address
        peer_ip: Option<IpAddr>,
    },

    /// Disconnected
    Disconnected {
        /// Reason for disconnection
        reason: String,
    },

    /// New client connected (server only)
    ClientConnected {
        /// Client session ID
        session_id: u32,
        /// Assigned IP address
        assigned_ip: IpAddr,
    },

    /// Client disconnected (server only)
    ClientDisconnected {
        /// Client session ID
        session_id: u32,
        /// Reason
        reason: String,
    },

    /// Statistics update
    StatsUpdate(VpnStats),

    /// Error occurred
    Error {
        /// Error message
        message: String,
        /// Whether the error is recoverable
        recoverable: bool,
    },

    /// Log message
    Log {
        /// Log level
        level: LogLevel,
        /// Message
        message: String,
    },
}

/// Log levels for VPN events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// Event handler trait for receiving VPN events
#[async_trait::async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle a VPN event
    async fn on_event(&self, event: VpnEvent);
}

/// Simple event handler that logs events
pub struct LoggingEventHandler;

#[async_trait::async_trait]
impl EventHandler for LoggingEventHandler {
    async fn on_event(&self, event: VpnEvent) {
        match event {
            VpnEvent::StateChanged { old, new } => {
                log::info!("VPN state: {} -> {}", old, new);
            }
            VpnEvent::Connected { tunnel_ip, peer_ip } => {
                if let Some(peer) = peer_ip {
                    log::info!("Connected: tunnel={}, peer={}", tunnel_ip, peer);
                } else {
                    log::info!("Connected: tunnel={}", tunnel_ip);
                }
            }
            VpnEvent::Disconnected { reason } => {
                log::info!("Disconnected: {}", reason);
            }
            VpnEvent::ClientConnected {
                session_id,
                assigned_ip,
            } => {
                log::info!(
                    "Client connected: session={}, ip={}",
                    session_id,
                    assigned_ip
                );
            }
            VpnEvent::ClientDisconnected { session_id, reason } => {
                log::info!("Client disconnected: session={}, reason={}", session_id, reason);
            }
            VpnEvent::StatsUpdate(stats) => {
                log::debug!(
                    "Stats: rx={} tx={} sessions={}",
                    stats.bytes_rx,
                    stats.bytes_tx,
                    stats.active_sessions
                );
            }
            VpnEvent::Error {
                message,
                recoverable,
            } => {
                if recoverable {
                    log::warn!("Recoverable error: {}", message);
                } else {
                    log::error!("Error: {}", message);
                }
            }
            VpnEvent::Log { level, message } => match level {
                LogLevel::Debug => log::debug!("{}", message),
                LogLevel::Info => log::info!("{}", message),
                LogLevel::Warning => log::warn!("{}", message),
                LogLevel::Error => log::error!("{}", message),
            },
        }
    }
}
