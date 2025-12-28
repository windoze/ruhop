//! Control socket for IPC with running VPN instances
//!
//! This module provides a Unix domain socket (or named pipe on Windows)
//! interface for querying and controlling a running VPN server or client.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

use crate::error::{Error, Result};
use crate::event::VpnState;

/// Default socket path for the control socket
#[cfg(unix)]
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/ruhop.sock";

#[cfg(windows)]
pub const DEFAULT_SOCKET_PATH: &str = r"\\.\pipe\ruhop";

/// Request messages sent to the control socket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlRequest {
    /// Get current status and statistics
    #[serde(rename = "status")]
    Status,

    /// Get list of connected clients (server only)
    #[serde(rename = "clients")]
    Clients,

    /// Request graceful shutdown
    #[serde(rename = "shutdown")]
    Shutdown,
}

/// Response messages from the control socket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlResponse {
    /// Status response
    #[serde(rename = "status")]
    Status(StatusInfo),

    /// Connected clients list
    #[serde(rename = "clients")]
    Clients(ClientsInfo),

    /// Error response
    #[serde(rename = "error")]
    Error { message: String },

    /// Success acknowledgment
    #[serde(rename = "ok")]
    Ok,
}

/// VPN status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    /// Current VPN state
    pub state: String,
    /// Role (server or client)
    pub role: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Bytes received
    pub bytes_rx: u64,
    /// Bytes transmitted
    pub bytes_tx: u64,
    /// Packets received
    pub packets_rx: u64,
    /// Packets transmitted
    pub packets_tx: u64,
    /// Number of active sessions (server only)
    pub active_sessions: usize,
    /// Local tunnel IP (if connected)
    pub tunnel_ip: Option<String>,
    /// Peer IP (if connected)
    pub peer_ip: Option<String>,
    /// TUN device name (if connected)
    pub tun_name: Option<String>,
    /// Blacklisted endpoints (client only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blacklisted_endpoints: Vec<BlacklistedEndpoint>,
}

/// Information about a blacklisted endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistedEndpoint {
    /// The endpoint address
    pub addr: String,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f32,
}

/// Information about a connected client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Session ID
    pub session_id: u32,
    /// Assigned IP address
    pub assigned_ip: String,
    /// Connection duration in seconds
    pub connected_secs: u64,
    /// Bytes received from this client
    pub bytes_rx: u64,
    /// Bytes transmitted to this client
    pub bytes_tx: u64,
}

/// List of connected clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientsInfo {
    /// List of connected clients
    pub clients: Vec<ClientInfo>,
}

/// Shared state for the control socket server
pub struct ControlState {
    /// Current VPN state
    pub state: VpnState,
    /// VPN role
    pub role: String,
    /// Start time
    pub start_time: std::time::Instant,
    /// Local tunnel IP
    pub tunnel_ip: Option<IpAddr>,
    /// Peer IP
    pub peer_ip: Option<IpAddr>,
    /// TUN device name
    pub tun_name: Option<String>,
    /// Connected clients (server only)
    pub clients: Vec<ClientInfo>,
    /// Shutdown sender
    pub shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
    /// Blacklisted endpoints (client only)
    pub blacklisted_endpoints: Vec<BlacklistedEndpoint>,
}

impl ControlState {
    /// Create new control state
    pub fn new(role: &str) -> Self {
        Self {
            state: VpnState::Disconnected,
            role: role.to_string(),
            start_time: std::time::Instant::now(),
            tunnel_ip: None,
            peer_ip: None,
            tun_name: None,
            clients: Vec::new(),
            shutdown_tx: None,
            blacklisted_endpoints: Vec::new(),
        }
    }

    /// Convert to status info (with stats from shared stats)
    pub fn to_status_info(&self, stats: &StatsSnapshot) -> StatusInfo {
        StatusInfo {
            state: format!("{:?}", self.state),
            role: self.role.clone(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            bytes_rx: stats.bytes_rx,
            bytes_tx: stats.bytes_tx,
            packets_rx: stats.packets_rx,
            packets_tx: stats.packets_tx,
            active_sessions: stats.active_sessions,
            tunnel_ip: self.tunnel_ip.map(|ip| ip.to_string()),
            peer_ip: self.peer_ip.map(|ip| ip.to_string()),
            tun_name: self.tun_name.clone(),
            blacklisted_endpoints: self.blacklisted_endpoints.clone(),
        }
    }
}

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Shared statistics using atomic counters for lock-free access
#[derive(Debug, Default)]
pub struct SharedStats {
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub packets_rx: AtomicU64,
    pub packets_tx: AtomicU64,
    pub active_sessions: AtomicUsize,
}

impl SharedStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record received bytes
    pub fn record_rx(&self, bytes: usize) {
        self.bytes_rx.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_rx.fetch_add(1, Ordering::Relaxed);
    }

    /// Record transmitted bytes
    pub fn record_tx(&self, bytes: usize) {
        self.bytes_tx.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_tx.fetch_add(1, Ordering::Relaxed);
    }

    /// Set active sessions count
    pub fn set_active_sessions(&self, count: usize) {
        self.active_sessions.store(count, Ordering::Relaxed);
    }

    /// Get a snapshot of current stats
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            packets_rx: self.packets_rx.load(Ordering::Relaxed),
            packets_tx: self.packets_tx.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of stats at a point in time
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub active_sessions: usize,
}

/// Reference to shared stats
pub type SharedStatsRef = Arc<SharedStats>;

/// Control socket server
pub struct ControlServer {
    socket_path: PathBuf,
    control_state: Arc<RwLock<ControlState>>,
    shared_stats: SharedStatsRef,
}

impl ControlServer {
    /// Create a new control server
    pub fn new(
        socket_path: impl AsRef<Path>,
        control_state: Arc<RwLock<ControlState>>,
        shared_stats: SharedStatsRef,
    ) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            control_state,
            shared_stats,
        }
    }

    /// Start the control server
    #[cfg(unix)]
    pub async fn start(&self) -> Result<()> {
        use tokio::net::UnixListener;

        // Remove existing socket file
        let _ = std::fs::remove_file(&self.socket_path);

        // Create parent directory if needed
        if let Some(parent) = self.socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| Error::Config(format!("Failed to bind control socket: {}", e)))?;

        // Set socket permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&self.socket_path, perms);
        }

        log::info!("Control socket listening on {:?}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let control_state = self.control_state.clone();
                    let shared_stats = self.shared_stats.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_connection_unix(stream, control_state, shared_stats).await
                        {
                            log::debug!("Control connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    log::warn!("Control socket accept error: {}", e);
                }
            }
        }
    }

    #[cfg(unix)]
    async fn handle_connection_unix(
        stream: tokio::net::UnixStream,
        control_state: Arc<RwLock<ControlState>>,
        shared_stats: SharedStatsRef,
    ) -> Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Read request (single line JSON)
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Config(format!("Failed to read request: {}", e)))?;

        let request: ControlRequest = serde_json::from_str(line.trim())
            .map_err(|e| Error::Config(format!("Invalid request: {}", e)))?;

        let response = Self::handle_request(request, &control_state, &shared_stats).await;

        let response_json = serde_json::to_string(&response)
            .map_err(|e| Error::Config(format!("Failed to serialize response: {}", e)))?;

        writer
            .write_all(response_json.as_bytes())
            .await
            .map_err(|e| Error::Config(format!("Failed to write response: {}", e)))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| Error::Config(format!("Failed to write newline: {}", e)))?;

        Ok(())
    }

    /// Start the control server (Windows named pipe implementation)
    #[cfg(windows)]
    pub async fn start(&self) -> Result<()> {
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name = self.socket_path.to_string_lossy().to_string();

        log::info!("Control socket listening on {}", pipe_name);

        // Create first pipe instance
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .map_err(|e| Error::Config(format!("Failed to create named pipe: {}", e)))?;

        loop {
            // Wait for a client to connect
            if let Err(e) = server.connect().await {
                log::warn!("Failed to accept pipe connection: {}", e);
                continue;
            }

            let control_state = self.control_state.clone();
            let shared_stats = self.shared_stats.clone();

            // Create a new pipe instance for the next client before handling this one
            let new_server = match ServerOptions::new().create(&pipe_name) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("Failed to create next pipe instance: {}", e);
                    continue;
                }
            };

            // Take ownership of the connected pipe and give the new one to the server
            let connected_pipe = std::mem::replace(&mut server, new_server);

            // Handle the connection in a separate task
            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_connection_windows(connected_pipe, control_state, shared_stats)
                        .await
                {
                    log::debug!("Control connection error: {}", e);
                }
            });
        }
    }

    #[cfg(windows)]
    async fn handle_connection_windows(
        pipe: tokio::net::windows::named_pipe::NamedPipeServer,
        control_state: Arc<RwLock<ControlState>>,
        shared_stats: SharedStatsRef,
    ) -> Result<()> {
        let (reader, mut writer) = tokio::io::split(pipe);
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Read request (single line JSON)
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| Error::Config(format!("Failed to read request: {}", e)))?;

        if line.is_empty() {
            return Ok(()); // Client disconnected
        }

        let request: ControlRequest = serde_json::from_str(line.trim())
            .map_err(|e| Error::Config(format!("Invalid request: {}", e)))?;

        let response = Self::handle_request(request, &control_state, &shared_stats).await;

        let response_json = serde_json::to_string(&response)
            .map_err(|e| Error::Config(format!("Failed to serialize response: {}", e)))?;

        writer
            .write_all(response_json.as_bytes())
            .await
            .map_err(|e| Error::Config(format!("Failed to write response: {}", e)))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| Error::Config(format!("Failed to write newline: {}", e)))?;
        writer
            .flush()
            .await
            .map_err(|e| Error::Config(format!("Failed to flush: {}", e)))?;

        Ok(())
    }

    async fn handle_request(
        request: ControlRequest,
        control_state: &Arc<RwLock<ControlState>>,
        shared_stats: &SharedStatsRef,
    ) -> ControlResponse {
        match request {
            ControlRequest::Status => {
                let ctrl = control_state.read().await;
                let stats = shared_stats.snapshot();
                ControlResponse::Status(ctrl.to_status_info(&stats))
            }
            ControlRequest::Clients => {
                let ctrl = control_state.read().await;
                ControlResponse::Clients(ClientsInfo {
                    clients: ctrl.clients.clone(),
                })
            }
            ControlRequest::Shutdown => {
                let ctrl = control_state.read().await;
                if let Some(ref tx) = ctrl.shutdown_tx {
                    let _ = tx.send(());
                    ControlResponse::Ok
                } else {
                    ControlResponse::Error {
                        message: "Shutdown not available".into(),
                    }
                }
            }
        }
    }

    /// Cleanup the socket file (Unix only - Windows named pipes are automatically cleaned up)
    #[cfg(unix)]
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }

    /// Cleanup (no-op on Windows - named pipes are automatically cleaned up)
    #[cfg(windows)]
    pub fn cleanup(&self) {
        // Named pipes are automatically cleaned up when the server closes
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Control socket client for querying a running VPN instance
pub struct ControlClient {
    socket_path: PathBuf,
}

impl ControlClient {
    /// Create a new control client
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Send a request and get a response
    #[cfg(unix)]
    pub async fn request(&self, request: ControlRequest) -> Result<ControlResponse> {
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            Error::Config(format!(
                "Failed to connect to control socket at {:?}: {}. Is the VPN running?",
                self.socket_path, e
            ))
        })?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send request
        let request_json = serde_json::to_string(&request)
            .map_err(|e| Error::Config(format!("Failed to serialize request: {}", e)))?;
        writer
            .write_all(request_json.as_bytes())
            .await
            .map_err(|e| Error::Config(format!("Failed to send request: {}", e)))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| Error::Config(format!("Failed to send newline: {}", e)))?;

        // Read response
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .map_err(|_| Error::Config("Timeout waiting for response".into()))?
            .map_err(|e| Error::Config(format!("Failed to read response: {}", e)))?;

        let response: ControlResponse = serde_json::from_str(line.trim())
            .map_err(|e| Error::Config(format!("Invalid response: {}", e)))?;

        Ok(response)
    }

    /// Send a request and get a response (Windows named pipe implementation)
    #[cfg(windows)]
    pub async fn request(&self, request: ControlRequest) -> Result<ControlResponse> {
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe_name = self.socket_path.to_string_lossy().to_string();

        // Try to connect with retries (pipe might be busy)
        let pipe = {
            let mut attempts = 0;
            loop {
                match ClientOptions::new().open(&pipe_name) {
                    Ok(pipe) => break pipe,
                    Err(_e) if attempts < 3 => {
                        // Pipe might be busy, wait and retry
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        attempts += 1;
                    }
                    Err(e) => {
                        return Err(Error::Config(format!(
                            "Failed to connect to control socket at {}: {}. Is the VPN running?",
                            pipe_name, e
                        )));
                    }
                }
            }
        };

        let (reader, mut writer) = tokio::io::split(pipe);
        let mut reader = BufReader::new(reader);

        // Send request
        let request_json = serde_json::to_string(&request)
            .map_err(|e| Error::Config(format!("Failed to serialize request: {}", e)))?;
        writer
            .write_all(request_json.as_bytes())
            .await
            .map_err(|e| Error::Config(format!("Failed to send request: {}", e)))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| Error::Config(format!("Failed to send newline: {}", e)))?;
        writer
            .flush()
            .await
            .map_err(|e| Error::Config(format!("Failed to flush: {}", e)))?;

        // Read response
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .map_err(|_| Error::Config("Timeout waiting for response".into()))?
            .map_err(|e| Error::Config(format!("Failed to read response: {}", e)))?;

        let response: ControlResponse = serde_json::from_str(line.trim())
            .map_err(|e| Error::Config(format!("Invalid response: {}", e)))?;

        Ok(response)
    }

    /// Get status from the running VPN
    pub async fn status(&self) -> Result<StatusInfo> {
        match self.request(ControlRequest::Status).await? {
            ControlResponse::Status(info) => Ok(info),
            ControlResponse::Error { message } => Err(Error::Config(message)),
            _ => Err(Error::Config("Unexpected response".into())),
        }
    }

    /// Get connected clients (server only)
    pub async fn clients(&self) -> Result<ClientsInfo> {
        match self.request(ControlRequest::Clients).await? {
            ControlResponse::Clients(info) => Ok(info),
            ControlResponse::Error { message } => Err(Error::Config(message)),
            _ => Err(Error::Config("Unexpected response".into())),
        }
    }

    /// Request shutdown
    pub async fn shutdown(&self) -> Result<()> {
        match self.request(ControlRequest::Shutdown).await? {
            ControlResponse::Ok => Ok(()),
            ControlResponse::Error { message } => Err(Error::Config(message)),
            _ => Err(Error::Config("Unexpected response".into())),
        }
    }
}
