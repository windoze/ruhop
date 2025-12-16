//! VPN engine implementation
//!
//! This module contains the main VPN engine that handles both server and client modes.

use rand::prelude::IndexedRandom;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::interval;

use hop_protocol::{
    AssignedAddresses, Cipher, IpAddress, Ipv4Pool, Packet, Session, SessionId,
    SessionState,
};
use hop_tun::{Route, RouteManager, TunConfig, TunDevice};

use crate::config::{ClientConfig, CommonConfig, Config, ServerConfig};
use crate::control::{ControlServer, ControlState, SharedStats, SharedStatsRef, DEFAULT_SOCKET_PATH};
use crate::error::{Error, Result};
use crate::event::{EventHandler, LogLevel, LoggingEventHandler, VpnEvent, VpnState, VpnStats};
use crate::script::{run_connect_script, run_disconnect_script, ScriptParams};

/// VPN role (server or client)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnRole {
    Server,
    Client,
}

impl std::fmt::Display for VpnRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnRole::Server => write!(f, "Server"),
            VpnRole::Client => write!(f, "Client"),
        }
    }
}

/// Client session information (for server mode)
struct ClientSession {
    session: Session,
    peer_addr: SocketAddr,
    last_activity: Instant,
    address_pair: hop_protocol::AddressPair,
    /// Index of the socket that most recently received a packet from this client.
    /// Server must reply from this socket for NAT traversal to work.
    last_recv_socket_idx: usize,
}

/// Internal engine state
struct EngineState {
    state: VpnState,
    stats: VpnStats,
    connected_at: Option<Instant>,
}

impl EngineState {
    fn new() -> Self {
        Self {
            state: VpnState::Disconnected,
            stats: VpnStats::new(),
            connected_at: None,
        }
    }
}

/// VPN engine for managing VPN connections
///
/// The engine can operate in either server or client mode based on the configuration.
/// It handles:
/// - TUN device creation and management
/// - UDP socket for hop protocol communication
/// - Session management and handshake
/// - Packet encryption/decryption
/// - Route management
pub struct VpnEngine {
    /// Configuration
    config: Config,

    /// Current role
    role: VpnRole,

    /// Event handler
    event_handler: Arc<dyn EventHandler>,

    /// Shutdown signal sender
    shutdown_tx: Option<broadcast::Sender<()>>,

    /// Engine state
    state: Arc<RwLock<EngineState>>,

    /// Control socket state (shared with control server)
    control_state: Arc<RwLock<ControlState>>,

    /// Shared statistics (atomic counters for lock-free access)
    shared_stats: SharedStatsRef,
}

impl VpnEngine {
    /// Create a new VPN engine with the given configuration and role
    pub fn new(config: Config, role: VpnRole) -> Result<Self> {
        config.validate()?;

        // Validate that the required config section exists
        match role {
            VpnRole::Server => {
                config.server_config()?;
            }
            VpnRole::Client => {
                config.client_config()?;
            }
        }

        let role_str = match role {
            VpnRole::Server => "server",
            VpnRole::Client => "client",
        };

        Ok(Self {
            config,
            role,
            event_handler: Arc::new(LoggingEventHandler),
            shutdown_tx: None,
            state: Arc::new(RwLock::new(EngineState::new())),
            control_state: Arc::new(RwLock::new(ControlState::new(role_str))),
            shared_stats: Arc::new(SharedStats::new()),
        })
    }

    /// Set a custom event handler
    pub fn with_event_handler(mut self, handler: Arc<dyn EventHandler>) -> Self {
        self.event_handler = handler;
        self
    }

    /// Get the current state
    pub async fn state(&self) -> VpnState {
        self.state.read().await.state
    }

    /// Get the current statistics
    pub async fn stats(&self) -> VpnStats {
        let state = self.state.read().await;
        let mut stats = state.stats.clone();
        if let Some(connected_at) = state.connected_at {
            stats.uptime = connected_at.elapsed();
        }
        stats
    }

    /// Start the VPN engine
    pub async fn start(&mut self) -> Result<()> {
        let current_state = self.state.read().await.state;
        if current_state.is_active() {
            return Err(Error::AlreadyRunning);
        }

        // Use existing shutdown channel if one was pre-created, otherwise create new
        let shutdown_tx = if let Some(tx) = self.shutdown_tx.clone() {
            tx
        } else {
            let (tx, _) = broadcast::channel(1);
            self.shutdown_tx = Some(tx.clone());
            tx
        };

        // Store shutdown handle in control state
        {
            let mut ctrl_state = self.control_state.write().await;
            ctrl_state.shutdown_tx = Some(shutdown_tx.clone());
        }

        // Start control socket server if configured
        let socket_path = self.config.common.control_socket.clone()
            .unwrap_or_else(|| DEFAULT_SOCKET_PATH.to_string());

        let control_state = self.control_state.clone();
        let shared_stats = self.shared_stats.clone();
        let control_server = ControlServer::new(&socket_path, control_state, shared_stats);

        // Spawn control server in background
        tokio::spawn(async move {
            if let Err(e) = control_server.start().await {
                log::warn!("Control socket error: {}", e);
            }
        });

        match self.role {
            VpnRole::Server => self.start_server(shutdown_tx).await,
            VpnRole::Client => self.start_client(shutdown_tx).await,
        }
    }

    /// Get a shutdown handle that can be used to stop the engine from outside
    ///
    /// Returns None if the engine hasn't been started yet.
    pub fn shutdown_handle(&self) -> Option<broadcast::Sender<()>> {
        self.shutdown_tx.clone()
    }

    /// Create a shutdown handle before starting the engine
    ///
    /// This allows the caller to keep a handle that can be used to stop
    /// the engine after it has been moved into a task.
    pub fn create_shutdown_handle(&mut self) -> broadcast::Sender<()> {
        let (shutdown_tx, _) = broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());
        shutdown_tx
    }

    /// Stop the VPN engine
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        self.set_state(VpnState::Disconnecting).await;

        // Wait a bit for graceful shutdown
        tokio::time::sleep(Duration::from_millis(100)).await;

        self.set_state(VpnState::Disconnected).await;
        Ok(())
    }

    /// Update state and emit event
    async fn set_state(&self, new_state: VpnState) {
        let old_state = {
            let mut state = self.state.write().await;
            let old = state.state;
            state.state = new_state;
            if new_state == VpnState::Connected {
                state.connected_at = Some(Instant::now());
            } else if new_state == VpnState::Disconnected {
                state.connected_at = None;
            }
            old
        };

        // Update control state
        {
            let mut ctrl_state = self.control_state.write().await;
            ctrl_state.state = new_state;
            if new_state == VpnState::Connected {
                ctrl_state.start_time = std::time::Instant::now();
            }
        }

        if old_state != new_state {
            self.emit_event(VpnEvent::StateChanged {
                old: old_state,
                new: new_state,
            })
            .await;
        }
    }

    /// Emit an event to the handler
    async fn emit_event(&self, event: VpnEvent) {
        self.event_handler.on_event(event).await;
    }

    /// Log a message through the event system
    async fn log(&self, level: LogLevel, message: impl Into<String>) {
        self.emit_event(VpnEvent::Log {
            level,
            message: message.into(),
        })
        .await;
    }

    // ========================================================================
    // Server Mode Implementation
    // ========================================================================

    async fn start_server(&self, shutdown_tx: broadcast::Sender<()>) -> Result<()> {
        let server_config = self.config.server_config()?;
        let common_config = &self.config.common;

        self.set_state(VpnState::Connecting).await;
        self.log(LogLevel::Info, format!("Starting VPN server on {}", server_config.listen)).await;

        // Create cipher
        let cipher = create_cipher(common_config);

        // Create IP pool for address allocation
        let pool = Arc::new(Mutex::new(
            Ipv4Pool::from_cidr(&server_config.tunnel_network)
                .map_err(|e| Error::Config(format!("invalid tunnel_network: {}", e)))?,
        ));

        // Create TUN device
        // On macOS, don't set a name - let the system assign a utun device
        #[allow(unused_mut)] // mut needed on non-macOS platforms
        let mut tun_builder = TunConfig::builder();
        #[cfg(not(target_os = "macos"))]
        {
            tun_builder = tun_builder.name("ruhop");
        }
        let tunnel_ip = server_config.get_tunnel_ip()?;
        let tun_config = tun_builder
            .ipv4(tunnel_ip, server_config.tunnel_net()?.prefix_len())
            .mtu(common_config.mtu)
            .build()?;

        let tun = TunDevice::create(tun_config).await?;
        let tun_name = tun.name().to_string();
        self.log(LogLevel::Info, format!("Created TUN device: {}", tun_name)).await;

        // Bind UDP sockets for all ports in the port range
        let listen_ip = server_config.listen;
        let mut sockets = Vec::new();
        for port in server_config.port_range[0]..=server_config.port_range[1] {
            let addr = SocketAddr::new(listen_ip, port);
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|e| Error::Connection(format!("failed to bind UDP socket on {}: {}", addr, e)))?;
            sockets.push(Arc::new(socket));
        }
        self.log(
            LogLevel::Info,
            format!(
                "Listening on {}:{}-{}",
                listen_ip, server_config.port_range[0], server_config.port_range[1]
            ),
        )
        .await;

        // Setup routes
        let route_manager = RouteManager::new().await?;
        self.setup_server_routes(&route_manager, server_config, &tun_name).await?;

        // Setup NAT if enabled
        if server_config.enable_nat {
            self.setup_nat(server_config).await?;
        }

        self.set_state(VpnState::Connected).await;
        self.emit_event(VpnEvent::Connected {
            tunnel_ip: IpAddr::V4(tunnel_ip),
            peer_ip: None,
        })
        .await;

        // Run server main loop
        let result = self
            .run_server_loop(
                Arc::new(tun),
                sockets,
                cipher,
                pool,
                server_config.clone(),
                shutdown_tx,
                self.shared_stats.clone(),
            )
            .await;

        // Cleanup routes
        self.cleanup_server_routes(&route_manager, server_config, &tun_name).await;

        result
    }

    async fn setup_server_routes(
        &self,
        route_manager: &RouteManager,
        server_config: &ServerConfig,
        tun_name: &str,
    ) -> Result<()> {
        let tunnel_net = server_config.tunnel_net()?;
        let route = Route::interface_route(
            ipnet::IpNet::V4(tunnel_net),
            tun_name,
        );
        route_manager.add(&route).await?;
        self.log(LogLevel::Info, format!("Added route: {}", route)).await;
        Ok(())
    }

    async fn cleanup_server_routes(
        &self,
        route_manager: &RouteManager,
        server_config: &ServerConfig,
        tun_name: &str,
    ) {
        if let Ok(tunnel_net) = server_config.tunnel_net() {
            let route = Route::interface_route(ipnet::IpNet::V4(tunnel_net), tun_name);
            let _ = route_manager.delete(&route).await;
        }
    }

    async fn setup_nat(&self, _server_config: &ServerConfig) -> Result<()> {
        // NAT setup is platform-specific and handled by hop_tun::NatManager
        // For now, we just log that NAT should be enabled
        self.log(LogLevel::Info, "NAT enabled (ensure iptables/pf rules are configured)").await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_server_loop(
        &self,
        tun: Arc<TunDevice>,
        sockets: Vec<Arc<UdpSocket>>,
        cipher: Cipher,
        pool: Arc<Mutex<Ipv4Pool>>,
        server_config: ServerConfig,
        shutdown_tx: broadcast::Sender<()>,
        shared_stats: SharedStatsRef,
    ) -> Result<()> {
        let mut shutdown_rx = shutdown_tx.subscribe();

        // Client sessions: SessionId -> ClientSession
        let sessions: Arc<RwLock<HashMap<u32, ClientSession>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // IP to SessionId mapping for routing packets from TUN
        let ip_to_session: Arc<RwLock<HashMap<Ipv4Addr, u32>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let event_handler = self.event_handler.clone();

        // Wrap sockets in Arc for sharing
        let sockets = Arc::new(sockets);

        // Spawn TUN -> UDP task
        // Use first socket for outbound (server responds on same port it received on,
        // but for simplicity we use random socket from the pool)
        let tun_read = tun.clone();
        let sockets_write = sockets.clone();
        let sessions_read = sessions.clone();
        let ip_to_session_read = ip_to_session.clone();
        let cipher_encrypt = cipher.clone();
        let stats_tun = shared_stats.clone();

        let tun_to_udp = tokio::spawn(async move {
            let mut buf = vec![0u8; 2000];
            loop {
                match tun_read.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        // Extract destination IP from IP packet
                        if let Some(dst_ip) = extract_dst_ipv4(&buf[..n]) {
                            let sessions = sessions_read.read().await;
                            let ip_map = ip_to_session_read.read().await;

                            if let Some(&sid) = ip_map.get(&dst_ip) {
                                if let Some(client) = sessions.get(&sid) {
                                    // Create data packet
                                    let packet = Packet::data(
                                        client.session.next_seq,
                                        sid,
                                        buf[..n].to_vec(),
                                    );

                                    // Encrypt and send via last received socket for NAT traversal
                                    match cipher_encrypt.encrypt(&packet, 0) {
                                        Ok(encrypted) => {
                                            // Use the socket that last received from this client
                                            let socket = &sockets_write[client.last_recv_socket_idx];
                                            let _ = socket
                                                .send_to(&encrypted, client.peer_addr)
                                                .await;

                                            // Update stats (lock-free)
                                            stats_tun.record_tx(encrypted.len());
                                        }
                                        Err(e) => {
                                            log::error!("Encryption error: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Spawn UDP -> TUN tasks for each socket
        let mut udp_tasks = Vec::new();
        for (socket_idx, socket) in sockets.iter().enumerate() {
            let tun_write = tun.clone();
            let socket_read = socket.clone();
            let sessions_write = sessions.clone();
            let ip_to_session_write = ip_to_session.clone();
            let cipher_decrypt = cipher.clone();
            let pool_alloc = pool.clone();
            let stats_udp = shared_stats.clone();
            let event_handler_udp = event_handler.clone();
            let server_config_clone = server_config.clone();

            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 2000];
                loop {
                    match socket_read.recv_from(&mut buf).await {
                        Ok((n, peer_addr)) => {
                            // Update stats (lock-free)
                            stats_udp.record_rx(n);

                            // Decrypt packet
                            let packet = match cipher_decrypt.decrypt(&buf[..n]) {
                                Ok(p) => p,
                                Err(e) => {
                                    log::debug!("Decrypt error from {}: {}", peer_addr, e);
                                    continue;
                                }
                            };

                            let sid = packet.header.sid;
                            let flags = packet.header.flag;

                            // Handle different packet types
                            if flags.is_push() && !flags.is_ack() {
                                // Knock/heartbeat packet - initiate or refresh session
                                handle_server_knock_multi(
                                    &sessions_write,
                                    &ip_to_session_write,
                                    &pool_alloc,
                                    &server_config_clone,
                                    sid,
                                    peer_addr,
                                    socket_idx,
                                    &event_handler_udp,
                                    &stats_udp,
                                )
                                .await;
                            } else if flags.is_handshake() && !flags.is_ack() {
                                // Handshake request - reply via same socket for NAT traversal
                                handle_server_handshake(
                                    &sessions_write,
                                    &ip_to_session_write,
                                    &pool_alloc,
                                    &socket_read,
                                    &cipher_decrypt,
                                    &server_config_clone,
                                    sid,
                                    peer_addr,
                                    socket_idx,
                                    &event_handler_udp,
                                )
                                .await;
                            } else if flags.is_handshake() && flags.is_ack() {
                                // Handshake confirmation from client
                                let mut sessions = sessions_write.write().await;
                                if let Some(client) = sessions.get_mut(&sid) {
                                    // Update last recv socket for NAT traversal
                                    client.last_recv_socket_idx = socket_idx;
                                    client.last_activity = Instant::now();
                                    if client.session.state == SessionState::Handshake {
                                        if let Err(e) = client.session.complete_handshake_v2(
                                            client.address_pair.client.ip,
                                            client.address_pair.client.mask,
                                        ) {
                                            log::error!("Failed to complete handshake: {}", e);
                                        }
                                    }
                                }
                            } else if flags.is_finish() {
                                // Client disconnecting - reply via same socket for NAT traversal
                                handle_server_finish(
                                    &sessions_write,
                                    &ip_to_session_write,
                                    &pool_alloc,
                                    &socket_read,
                                    &cipher_decrypt,
                                    sid,
                                    peer_addr,
                                    &event_handler_udp,
                                    &stats_udp,
                                )
                                .await;
                            } else if flags.is_data() {
                                // Data packet - update last recv socket for NAT traversal
                                let mut sessions = sessions_write.write().await;
                                if let Some(client) = sessions.get_mut(&sid) {
                                    client.last_recv_socket_idx = socket_idx;
                                    client.last_activity = Instant::now();
                                    if client.session.state == SessionState::Working {
                                        // Write to TUN
                                        if let Err(e) = tun_write.write(&packet.payload).await {
                                            log::error!("TUN write error: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("UDP recv error: {}", e);
                            break;
                        }
                    }
                }
            });
            udp_tasks.push(task);
        }

        // Spawn heartbeat task
        let sessions_hb = sessions.clone();
        let stats_hb = shared_stats.clone();
        let heartbeat_interval = Duration::from_secs(self.config.common.heartbeat_interval);
        let session_timeout = Duration::from_secs(heartbeat_interval.as_secs() * 3);

        let heartbeat = tokio::spawn(async move {
            let mut ticker = interval(heartbeat_interval);
            loop {
                ticker.tick().await;

                let now = Instant::now();
                let mut sessions = sessions_hb.write().await;
                let expired: Vec<u32> = sessions
                    .iter()
                    .filter(|(_, s)| now.duration_since(s.last_activity) > session_timeout)
                    .map(|(sid, _)| *sid)
                    .collect();

                for sid in expired {
                    if let Some(_client) = sessions.remove(&sid) {
                        log::info!("Session {} timed out", SessionId::new(sid));
                        // Release IP address
                        // Note: pool cleanup would happen here
                    }
                }

                // Update active sessions count after removing expired sessions
                stats_hb.set_active_sessions(sessions.len());
            }
        });

        // Wait for shutdown or error
        // Use futures::future::select_all to wait on any UDP task
        let udp_tasks_future = async {
            if !udp_tasks.is_empty() {
                let (result, _idx, _remaining) = futures::future::select_all(udp_tasks).await;
                result
            } else {
                Ok(())
            }
        };

        tokio::select! {
            _ = shutdown_rx.recv() => {
                log::info!("Server shutdown requested");
            }
            _ = tun_to_udp => {
                log::error!("TUN to UDP task ended unexpectedly");
            }
            _ = udp_tasks_future => {
                log::error!("UDP to TUN task ended unexpectedly");
            }
        }

        // Cancel all tasks
        heartbeat.abort();

        self.emit_event(VpnEvent::Disconnected {
            reason: "Server stopped".to_string(),
        })
        .await;

        Ok(())
    }

    // ========================================================================
    // Client Mode Implementation
    // ========================================================================

    async fn start_client(&self, shutdown_tx: broadcast::Sender<()>) -> Result<()> {
        let client_config = self.config.client_config()?;
        let common_config = &self.config.common;

        self.set_state(VpnState::Connecting).await;
        self.log(LogLevel::Info, format!("Connecting to server: {:?}", client_config.server)).await;

        // Create cipher
        let cipher = create_cipher(common_config);

        // Resolve all server addresses (hosts × port range)
        let server_addrs = client_config.server_addrs()?;
        self.log(
            LogLevel::Info,
            format!(
                "Resolved {} server addresses ({} hosts × {} ports)",
                server_addrs.len(),
                client_config.resolve_server_ips()?.len(),
                client_config.port_range[1] - client_config.port_range[0] + 1
            ),
        )
        .await;

        // Get a random address for initial connection
        let initial_addr = client_config
            .random_server_addr(&server_addrs)
            .ok_or_else(|| Error::Config("no server addresses available".into()))?;

        // Create UDP socket
        let socket = Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| Error::Connection(format!("failed to bind UDP socket: {}", e)))?,
        );

        // Create session
        let mut session = Session::new_client();
        let sid = session.id.value();

        // Perform port knocking
        self.set_state(VpnState::Handshaking).await;
        self.log(LogLevel::Info, "Performing handshake...").await;

        // Send knock packets to multiple random addresses for port knocking
        let knock = Packet::knock(sid);
        let encrypted = cipher.encrypt(&knock, 0)?;
        // Send knock to a few random addresses
        for _ in 0..std::cmp::min(5, server_addrs.len()) {
            if let Some(addr) = client_config.random_server_addr(&server_addrs) {
                socket.send_to(&encrypted, addr).await?;
            }
        }

        // Start handshake
        session.start_handshake()?;

        // Send handshake request to a random address
        let hs_req = Packet::handshake_request(sid);
        let encrypted = cipher.encrypt(&hs_req, 0)?;
        let hs_addr = client_config
            .random_server_addr(&server_addrs)
            .unwrap_or(initial_addr);
        socket.send_to(&encrypted, hs_addr).await?;

        // Wait for handshake response
        let mut buf = vec![0u8; 2000];
        let handshake_timeout = Duration::from_secs(10);
        let server_addrs_clone = server_addrs.clone();
        let assigned_ip = tokio::time::timeout(handshake_timeout, async {
            loop {
                let (n, _) = socket.recv_from(&mut buf).await?;
                let packet = cipher.decrypt(&buf[..n])?;

                if packet.header.flag.is_handshake_ack() && packet.header.sid == sid {
                    let (_, ip, mask) = packet.parse_handshake_response_v2()?;
                    session.complete_handshake_v2(ip, mask)?;

                    // Send confirmation to a random address
                    let confirm = Packet::handshake_confirm(sid);
                    let encrypted = cipher.encrypt(&confirm, 0)?;
                    let confirm_addr = server_addrs_clone
                        .choose(&mut rand::rng())
                        .copied()
                        .unwrap_or(initial_addr);
                    socket.send_to(&encrypted, confirm_addr).await?;

                    return Ok::<_, Error>((ip, mask));
                }
            }
        })
        .await
        .map_err(|_| Error::Timeout("handshake timeout".to_string()))??;

        let (tunnel_ip, mask) = assigned_ip;
        self.log(LogLevel::Info, format!("Assigned IP: {}/{}", tunnel_ip, mask)).await;

        // Create TUN device with assigned IP
        let server_tunnel_ip = match &tunnel_ip {
            IpAddress::V4(ip) => {
                let octets = ip.octets();
                // Server peer is typically our IP - 1
                Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3].saturating_sub(1))
            }
            _ => return Err(Error::Config("IPv6 not yet supported for client".to_string())),
        };

        let tunnel_ipv4 = match tunnel_ip {
            IpAddress::V4(ip) => ip,
            _ => return Err(Error::Config("IPv6 not yet supported for client".to_string())),
        };

        // On macOS, don't set a name - let the system assign a utun device
        #[allow(unused_mut)] // mut needed on non-macOS platforms
        let mut tun_builder = TunConfig::builder();
        #[cfg(not(target_os = "macos"))]
        {
            tun_builder = tun_builder.name("ruhop");
        }
        let tun_config = tun_builder
            .ipv4_with_dest(tunnel_ipv4, mask, server_tunnel_ip)
            .mtu(common_config.mtu)
            .build()?;

        let tun = TunDevice::create(tun_config).await?;
        let tun_name = tun.name().to_string();
        self.log(LogLevel::Info, format!("Created TUN device: {}", tun_name)).await;

        // Setup routes
        let route_manager = RouteManager::new().await?;
        let server_ips = client_config.resolve_server_ips()?;
        let original_gateway = route_manager.get_default_gateway().await?;
        self.setup_client_routes(&route_manager, client_config, &tun_name, server_tunnel_ip, &server_ips, original_gateway)
            .await?;

        self.set_state(VpnState::Connected).await;
        self.emit_event(VpnEvent::Connected {
            tunnel_ip: IpAddr::V4(tunnel_ipv4),
            peer_ip: Some(IpAddr::V4(server_tunnel_ip)),
        })
        .await;

        // Run on_connect script if configured
        let script_params = ScriptParams::new(
            IpAddr::V4(tunnel_ipv4),
            IpAddr::V4(server_tunnel_ip),
            mask,
            &tun_name,
        );

        if let Err(e) = run_connect_script(client_config.on_connect.as_deref(), &script_params).await {
            self.log(LogLevel::Error, format!("on_connect script failed: {}", e)).await;
            // Continue anyway - script failure shouldn't prevent VPN from working
        }

        // Run client main loop
        let result = self
            .run_client_loop(
                Arc::new(tun),
                socket,
                cipher,
                session,
                server_addrs,
                shutdown_tx,
                self.shared_stats.clone(),
            )
            .await;

        // Run on_disconnect script if configured
        run_disconnect_script(client_config.on_disconnect.as_deref(), &script_params).await;

        // Cleanup routes
        self.cleanup_client_routes(&route_manager, client_config, &tun_name, server_tunnel_ip, &server_ips, original_gateway)
            .await;

        result
    }

    async fn setup_client_routes(
        &self,
        route_manager: &RouteManager,
        client_config: &ClientConfig,
        tun_name: &str,
        tun_gateway: Ipv4Addr,
        server_ips: &[IpAddr],
        original_gateway: Option<IpAddr>,
    ) -> Result<()> {
        if client_config.route_all_traffic {
            // First, add routes for server IPs to use the original gateway
            // This prevents routing loops where VPN traffic gets sent through the VPN
            if let Some(orig_gw) = original_gateway {
                for server_ip in server_ips {
                    match server_ip {
                        IpAddr::V4(ip) => {
                            if let IpAddr::V4(gw) = orig_gw {
                                let route = Route::ipv4(*ip, 32, Some(gw))?;
                                if let Err(e) = route_manager.add(&route).await {
                                    self.log(
                                        LogLevel::Warning,
                                        format!("Failed to add server route for {}: {}", ip, e),
                                    )
                                    .await;
                                } else {
                                    self.log(
                                        LogLevel::Debug,
                                        format!("Added route for server {} via {}", ip, gw),
                                    )
                                    .await;
                                }
                            }
                        }
                        IpAddr::V6(ip) => {
                            if let IpAddr::V6(gw) = orig_gw {
                                let route = Route::ipv6(*ip, 128, Some(gw))?;
                                if let Err(e) = route_manager.add(&route).await {
                                    self.log(
                                        LogLevel::Warning,
                                        format!("Failed to add server route for {}: {}", ip, e),
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                }
            } else {
                self.log(
                    LogLevel::Warning,
                    "No default gateway found, server routes not added - VPN may not work correctly",
                )
                .await;
            }

            // Route all traffic through VPN
            // Split into two /1 routes to override default without removing it
            let route1 = Route::ipv4(Ipv4Addr::new(0, 0, 0, 0), 1, Some(tun_gateway))?
                .with_interface(tun_name);
            let route2 = Route::ipv4(Ipv4Addr::new(128, 0, 0, 0), 1, Some(tun_gateway))?
                .with_interface(tun_name);

            route_manager.add(&route1).await?;
            route_manager.add(&route2).await?;

            self.log(LogLevel::Info, "Routing all traffic through VPN").await;
        }

        Ok(())
    }

    async fn cleanup_client_routes(
        &self,
        route_manager: &RouteManager,
        client_config: &ClientConfig,
        tun_name: &str,
        tun_gateway: Ipv4Addr,
        server_ips: &[IpAddr],
        original_gateway: Option<IpAddr>,
    ) {
        if client_config.route_all_traffic {
            // Remove the catch-all routes
            if let Ok(route1) = Route::ipv4(Ipv4Addr::new(0, 0, 0, 0), 1, Some(tun_gateway)) {
                let _ = route_manager.delete(&route1.with_interface(tun_name)).await;
            }
            if let Ok(route2) = Route::ipv4(Ipv4Addr::new(128, 0, 0, 0), 1, Some(tun_gateway)) {
                let _ = route_manager.delete(&route2.with_interface(tun_name)).await;
            }

            // Remove server-specific routes
            if let Some(orig_gw) = original_gateway {
                for server_ip in server_ips {
                    match server_ip {
                        IpAddr::V4(ip) => {
                            if let IpAddr::V4(gw) = orig_gw {
                                if let Ok(route) = Route::ipv4(*ip, 32, Some(gw)) {
                                    let _ = route_manager.delete(&route).await;
                                }
                            }
                        }
                        IpAddr::V6(ip) => {
                            if let IpAddr::V6(gw) = orig_gw {
                                if let Ok(route) = Route::ipv6(*ip, 128, Some(gw)) {
                                    let _ = route_manager.delete(&route).await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_client_loop(
        &self,
        tun: Arc<TunDevice>,
        socket: Arc<UdpSocket>,
        cipher: Cipher,
        session: Session,
        server_addrs: Vec<SocketAddr>,
        shutdown_tx: broadcast::Sender<()>,
        shared_stats: SharedStatsRef,
    ) -> Result<()> {
        let mut shutdown_rx = shutdown_tx.subscribe();
        let sid = session.id.value();

        // Sequence number counter
        let seq = Arc::new(std::sync::atomic::AtomicU32::new(0));

        // Server addresses for port hopping
        let server_addrs = Arc::new(server_addrs);

        // Spawn TUN -> UDP task
        let tun_read = tun.clone();
        let socket_write = socket.clone();
        let cipher_encrypt = cipher.clone();
        let stats_tun = shared_stats.clone();
        let seq_tun = seq.clone();
        let server_addrs_tun = server_addrs.clone();

        let tun_to_udp = tokio::spawn(async move {
            let mut buf = vec![0u8; 2000];
            loop {
                match tun_read.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let seq_num = seq_tun.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let packet = Packet::data(seq_num, sid, buf[..n].to_vec());

                        match cipher_encrypt.encrypt(&packet, 0) {
                            Ok(encrypted) => {
                                // Port hopping: select random server address
                                let target_addr = server_addrs_tun
                                    .choose(&mut rand::rng())
                                    .copied()
                                    .unwrap_or(server_addrs_tun[0]);

                                if let Err(e) = socket_write.send_to(&encrypted, target_addr).await {
                                    log::error!("UDP send error: {}", e);
                                    break;
                                }

                                // Update stats (lock-free)
                                stats_tun.record_tx(encrypted.len());
                            }
                            Err(e) => {
                                log::error!("Encryption error: {}", e);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Spawn UDP -> TUN task
        let tun_write = tun.clone();
        let socket_read = socket.clone();
        let cipher_decrypt = cipher.clone();
        let stats_udp = shared_stats.clone();

        let udp_to_tun = tokio::spawn(async move {
            let mut buf = vec![0u8; 2000];
            loop {
                match socket_read.recv_from(&mut buf).await {
                    Ok((n, _)) => {
                        // Update stats (lock-free)
                        stats_udp.record_rx(n);

                        let packet = match cipher_decrypt.decrypt(&buf[..n]) {
                            Ok(p) => p,
                            Err(e) => {
                                log::debug!("Decrypt error: {}", e);
                                continue;
                            }
                        };

                        if packet.header.flag.is_data() {
                            if let Err(e) = tun_write.write(&packet.payload).await {
                                log::error!("TUN write error: {}", e);
                            }
                        } else if packet.header.flag.is_push() && packet.header.flag.is_ack() {
                            // Heartbeat response - connection is alive
                            log::debug!("Received heartbeat response");
                        }
                    }
                    Err(e) => {
                        log::error!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        });

        // Spawn heartbeat task
        let socket_hb = socket.clone();
        let cipher_hb = cipher.clone();
        let heartbeat_interval = Duration::from_secs(self.config.common.heartbeat_interval);
        let server_addrs_hb = server_addrs.clone();

        let heartbeat = tokio::spawn(async move {
            let mut ticker = interval(heartbeat_interval);
            loop {
                ticker.tick().await;

                let hb = Packet::heartbeat_request(sid);
                if let Ok(encrypted) = cipher_hb.encrypt(&hb, 0) {
                    // Port hopping: select random server address for heartbeat
                    let target_addr = server_addrs_hb
                        .choose(&mut rand::rng())
                        .copied()
                        .unwrap_or(server_addrs_hb[0]);
                    let _ = socket_hb.send_to(&encrypted, target_addr).await;
                }
            }
        });

        // Wait for shutdown or error
        tokio::select! {
            _ = shutdown_rx.recv() => {
                log::info!("Client shutdown requested");

                // Send FIN packet to a random server address
                let fin = Packet::finish_request(sid);
                if let Ok(encrypted) = cipher.encrypt(&fin, 0) {
                    let target_addr = server_addrs
                        .choose(&mut rand::rng())
                        .copied()
                        .unwrap_or(server_addrs[0]);
                    let _ = socket.send_to(&encrypted, target_addr).await;
                }
            }
            _ = tun_to_udp => {
                log::error!("TUN to UDP task ended unexpectedly");
            }
            _ = udp_to_tun => {
                log::error!("UDP to TUN task ended unexpectedly");
            }
        }

        heartbeat.abort();

        self.emit_event(VpnEvent::Disconnected {
            reason: "Client stopped".to_string(),
        })
        .await;

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_cipher(config: &CommonConfig) -> Cipher {
    if config.obfuscation {
        Cipher::with_obfuscation(config.key.as_bytes())
    } else {
        Cipher::new(config.key.as_bytes())
    }
}

fn extract_dst_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    Some(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}

/// Handle knock packet (multi-socket version without socket param)
#[allow(clippy::too_many_arguments)]
async fn handle_server_knock_multi(
    sessions: &RwLock<HashMap<u32, ClientSession>>,
    ip_to_session: &RwLock<HashMap<Ipv4Addr, u32>>,
    pool: &Mutex<Ipv4Pool>,
    server_config: &ServerConfig,
    sid: u32,
    peer_addr: SocketAddr,
    socket_idx: usize,
    _event_handler: &Arc<dyn EventHandler>,
    shared_stats: &SharedStatsRef,
) {
    let mut sessions_lock = sessions.write().await;

    // Check if session already exists
    if let Some(client) = sessions_lock.get_mut(&sid) {
        // Update last recv socket for NAT traversal
        client.last_recv_socket_idx = socket_idx;
        client.last_activity = Instant::now();
        return;
    }

    // Check max clients
    if sessions_lock.len() >= server_config.max_clients {
        log::warn!("Max clients reached, rejecting {}", peer_addr);
        return;
    }

    // Allocate IP address
    let address_pair = match pool.lock().await.allocate() {
        Ok(pair) => pair,
        Err(e) => {
            log::error!("IP allocation failed: {}", e);
            return;
        }
    };

    // Create session
    let session = Session::new_server(SessionId::new(sid));

    // Record session
    sessions_lock.insert(
        sid,
        ClientSession {
            session,
            peer_addr,
            last_activity: Instant::now(),
            address_pair,
            last_recv_socket_idx: socket_idx,
        },
    );

    // Update active sessions count
    shared_stats.set_active_sessions(sessions_lock.len());

    // Add IP mapping
    if let IpAddress::V4(ip) = address_pair.client.ip {
        ip_to_session.write().await.insert(ip, sid);
    }

    log::info!(
        "New client knock from {}: sid={}, assigned={}",
        peer_addr,
        SessionId::new(sid),
        address_pair.client.ip
    );
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_handshake(
    sessions: &RwLock<HashMap<u32, ClientSession>>,
    ip_to_session: &RwLock<HashMap<Ipv4Addr, u32>>,
    pool: &Mutex<Ipv4Pool>,
    socket: &UdpSocket,
    cipher: &Cipher,
    server_config: &ServerConfig,
    sid: u32,
    peer_addr: SocketAddr,
    socket_idx: usize,
    event_handler: &Arc<dyn EventHandler>,
) {
    let mut sessions_lock = sessions.write().await;

    // Get or create session
    let client = if let Some(c) = sessions_lock.get_mut(&sid) {
        // Update last recv socket for NAT traversal
        c.last_recv_socket_idx = socket_idx;
        c
    } else {
        // Session doesn't exist - might have been a knock we missed
        // Check max clients
        if sessions_lock.len() >= server_config.max_clients {
            log::warn!("Max clients reached, rejecting handshake from {}", peer_addr);
            return;
        }

        // Allocate IP
        let address_pair = match pool.lock().await.allocate() {
            Ok(pair) => pair,
            Err(e) => {
                log::error!("IP allocation failed: {}", e);
                return;
            }
        };

        let session = Session::new_server(SessionId::new(sid));

        sessions_lock.insert(
            sid,
            ClientSession {
                session,
                peer_addr,
                last_activity: Instant::now(),
                address_pair,
                last_recv_socket_idx: socket_idx,
            },
        );

        if let IpAddress::V4(ip) = address_pair.client.ip {
            ip_to_session.write().await.insert(ip, sid);
        }

        sessions_lock.get_mut(&sid).unwrap()
    };

    // Start handshake if in Init state
    if client.session.state == SessionState::Init {
        if let Err(e) = client.session.start_handshake() {
            log::error!("Failed to start handshake: {}", e);
            return;
        }
    }

    // Send handshake response with assigned IP
    let addresses = AssignedAddresses::single(
        client.address_pair.client.ip,
        client.address_pair.client.mask,
    );
    let response = Packet::handshake_response_multi_ip(sid, addresses);

    match cipher.encrypt(&response, 0) {
        Ok(encrypted) => {
            if let Err(e) = socket.send_to(&encrypted, peer_addr).await {
                log::error!("Failed to send handshake response: {}", e);
            } else {
                log::info!(
                    "Sent handshake response to {}: ip={}",
                    peer_addr,
                    client.address_pair.client.ip
                );

                event_handler
                    .on_event(VpnEvent::ClientConnected {
                        session_id: sid,
                        assigned_ip: match client.address_pair.client.ip {
                            IpAddress::V4(ip) => IpAddr::V4(ip),
                            IpAddress::V6(ip) => IpAddr::V6(ip),
                        },
                    })
                    .await;
            }
        }
        Err(e) => {
            log::error!("Failed to encrypt handshake response: {}", e);
        }
    }

    client.last_activity = Instant::now();
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_finish(
    sessions: &RwLock<HashMap<u32, ClientSession>>,
    ip_to_session: &RwLock<HashMap<Ipv4Addr, u32>>,
    pool: &Mutex<Ipv4Pool>,
    socket: &UdpSocket,
    cipher: &Cipher,
    sid: u32,
    peer_addr: SocketAddr,
    event_handler: &Arc<dyn EventHandler>,
    shared_stats: &SharedStatsRef,
) {
    let mut sessions_lock = sessions.write().await;

    if let Some(client) = sessions_lock.remove(&sid) {
        // Update active sessions count
        shared_stats.set_active_sessions(sessions_lock.len());

        // Send FIN ACK
        let fin_ack = Packet::finish_ack(sid);
        if let Ok(encrypted) = cipher.encrypt(&fin_ack, 0) {
            let _ = socket.send_to(&encrypted, peer_addr).await;
        }

        // Remove IP mapping
        if let IpAddress::V4(ip) = client.address_pair.client.ip {
            ip_to_session.write().await.remove(&ip);
        }

        // Release IP back to pool
        pool.lock().await.release(&client.address_pair.client.ip);

        log::info!(
            "Client {} disconnected: {}",
            SessionId::new(sid),
            client.address_pair.client.ip
        );

        event_handler
            .on_event(VpnEvent::ClientDisconnected {
                session_id: sid,
                reason: "Client requested disconnect".to_string(),
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dst_ipv4() {
        // Minimal IPv4 packet header (20 bytes)
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;

        let dst = extract_dst_ipv4(&packet);
        assert_eq!(dst, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_extract_dst_ipv4_too_short() {
        let packet = vec![0u8; 10];
        assert_eq!(extract_dst_ipv4(&packet), None);
    }

    #[test]
    fn test_extract_dst_ipv4_wrong_version() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x60; // IPv6
        assert_eq!(extract_dst_ipv4(&packet), None);
    }
}
