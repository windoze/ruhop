//! VPN engine implementation
//!
//! This module contains the main VPN engine that handles both server and client modes.

use rand::prelude::IndexedRandom;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::interval;

use crate::socket::{DualStackSocket, TrackedUdpSocket};

use hop_dns::{DnsClient, DnsProxy};
use hop_protocol::{
    AssignedAddresses, Cipher, IpAddress, Ipv4Pool, Packet, Session, SessionId, SessionState,
};
use hop_tun::{NatManager, Route, RouteManager, TunConfig, TunDevice};

use crate::config::{ClientConfig, CommonConfig, Config, ServerConfig};
use crate::control::{
    BlacklistedEndpoint, ControlServer, ControlState, SharedStats, SharedStatsRef,
    DEFAULT_SOCKET_PATH,
};
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
    /// Client's assigned address
    client_addr: hop_protocol::AssignedAddress,
    /// Index of the socket that most recently received a packet from this client.
    /// Server must reply from this socket for NAT traversal to work.
    last_recv_socket_idx: usize,
    /// Local address that received the most recent packet from this client.
    /// On multi-homed servers, responses must be sent from this address for NAT traversal.
    last_recv_local_addr: SocketAddr,
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
        let socket_path = self
            .config
            .common
            .control_socket
            .clone()
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

        self.set_state(VpnState::Starting).await;
        self.log(
            LogLevel::Info,
            format!("Starting VPN server on {}", server_config.listen),
        )
        .await;

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
        #[cfg(target_os = "macos")]
        {
            if common_config.tun_device.is_some() {
                log::info!(
                    "tun_device config is ignored on macOS (system auto-assigns utun device names)"
                );
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let device_name = common_config.tun_device.as_deref().unwrap_or("ruhop");
            tun_builder = tun_builder.name(device_name);
        }
        let tunnel_ip = server_config.get_tunnel_ip()?;
        let tun_config = tun_builder
            .ipv4(tunnel_ip, server_config.tunnel_net()?.prefix_len())
            .mtu(common_config.mtu)
            .build()?;

        let tun = TunDevice::create(tun_config).await?;
        let tun_name = tun.name().to_string();
        self.log(LogLevel::Info, format!("Created TUN device: {}", tun_name))
            .await;

        // Bind UDP sockets for all ports in the port range
        // Use TrackedUdpSocket for proper NAT traversal on multi-homed servers
        let listen_ip = server_config.listen;
        let mut sockets = Vec::new();
        for port in server_config.port_range[0]..=server_config.port_range[1] {
            let addr = SocketAddr::new(listen_ip, port);
            let socket = TrackedUdpSocket::bind(addr).await.map_err(|e| {
                Error::Connection(format!("failed to bind UDP socket on {}: {}", addr, e))
            })?;
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
        self.setup_server_routes(&route_manager, server_config, &tun_name)
            .await?;

        // Setup NAT if enabled
        let nat_manager = if server_config.enable_nat {
            self.setup_nat(server_config).await?
        } else {
            None
        };

        // Start DNS proxy if configured
        let dns_servers_for_handshake = self
            .setup_dns_proxy(server_config, tunnel_ip, shutdown_tx.clone())
            .await?;

        self.set_state(VpnState::Listening).await;

        // Update control state with tunnel IP and TUN name for status reporting
        {
            let mut ctrl_state = self.control_state.write().await;
            ctrl_state.tunnel_ip = Some(IpAddr::V4(tunnel_ip));
            ctrl_state.tun_name = Some(tun_name.clone());
            // peer_ip is not applicable for server mode
        }

        self.emit_event(VpnEvent::ServerReady {
            tunnel_ip: IpAddr::V4(tunnel_ip),
            port_range: (server_config.port_range[0], server_config.port_range[1]),
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
                dns_servers_for_handshake,
            )
            .await;

        // Cleanup routes
        self.cleanup_server_routes(&route_manager, server_config, &tun_name)
            .await;

        // Cleanup NAT (NatManager handles cleanup in Drop, but explicit cleanup is cleaner)
        if let Some(mut nat) = nat_manager {
            if let Err(e) = nat.cleanup() {
                self.log(LogLevel::Warning, format!("NAT cleanup error: {}", e))
                    .await;
            }
        }

        result
    }

    async fn setup_server_routes(
        &self,
        route_manager: &RouteManager,
        server_config: &ServerConfig,
        tun_name: &str,
    ) -> Result<()> {
        let tunnel_net = server_config.tunnel_net()?;
        let route = Route::interface_route(ipnet::IpNet::V4(tunnel_net), tun_name);
        route_manager.add(&route).await?;
        self.log(LogLevel::Info, format!("Added route: {}", route))
            .await;
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

    #[allow(unused_variables)]
    async fn setup_nat(&self, server_config: &ServerConfig) -> Result<Option<NatManager>> {
        #[cfg(target_os = "linux")]
        {
            // Detect the default outbound interface
            let out_iface = Self::detect_default_interface().await?;

            // Create NatManager with explicit backend selection
            let use_nftables = self.config.common.use_nftables;
            let mut nat_manager = NatManager::new(use_nftables)
                .map_err(|e| Error::Config(format!("Failed to initialize NAT manager: {}", e)))?;

            self.log(
                LogLevel::Info,
                format!(
                    "Setting up NAT using {:?} backend, outbound interface: {}",
                    nat_manager.backend(),
                    out_iface
                ),
            )
            .await;

            // Enable IP forwarding
            nat_manager
                .enable_ip_forwarding()
                .map_err(|e| Error::Config(format!("Failed to enable IP forwarding: {}", e)))?;

            // Add masquerade rule for tunnel network
            let rule = hop_tun::nat::NatRule::masquerade(&server_config.tunnel_network, &out_iface);
            nat_manager
                .add_rule(&rule)
                .map_err(|e| Error::Config(format!("Failed to add NAT rule: {}", e)))?;

            self.log(
                LogLevel::Info,
                format!(
                    "NAT enabled: {} -> {} (masquerade)",
                    server_config.tunnel_network, out_iface
                ),
            )
            .await;

            Ok(Some(nat_manager))
        }

        #[cfg(not(target_os = "linux"))]
        {
            self.log(
                LogLevel::Info,
                "NAT enabled (ensure firewall rules are configured)",
            )
            .await;
            Ok(None)
        }
    }

    #[cfg(target_os = "linux")]
    async fn detect_default_interface() -> Result<String> {
        use tokio::process::Command;

        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await
            .map_err(|e| Error::Config(format!("Failed to run ip route: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Config("Failed to get default route".into()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "default via X.X.X.X dev ethX ..."
        for part in stdout.split_whitespace().collect::<Vec<_>>().windows(2) {
            if part[0] == "dev" {
                return Ok(part[1].to_string());
            }
        }

        Err(Error::Config(
            "Could not determine default interface".into(),
        ))
    }

    /// Setup DNS proxy if configured and return DNS servers to push to clients
    async fn setup_dns_proxy(
        &self,
        server_config: &ServerConfig,
        tunnel_ip: Ipv4Addr,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Result<Vec<IpAddress>> {
        if !server_config.dns_proxy {
            // DNS proxy disabled - don't push any DNS servers
            return Ok(Vec::new());
        }

        // DNS proxy enabled - use configured upstreams or defaults
        let upstreams = if server_config.dns_servers.is_empty() {
            // Default upstream servers
            vec![
                hop_dns::DnsServerSpec::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                hop_dns::DnsServerSpec::Udp {
                    addr: "1.1.1.1:53".parse().unwrap(),
                },
            ]
        } else {
            server_config.parse_dns_servers()?
        };

        // Create DNS client with upstream servers
        let dns_client = Arc::new(DnsClient::new(upstreams.clone(), 1000)?);

        // Create and start DNS proxy
        let bind_addr = SocketAddr::new(IpAddr::V4(tunnel_ip), 53);
        let proxy = DnsProxy::new(bind_addr, dns_client, shutdown_tx.subscribe());

        self.log(
            LogLevel::Info,
            format!(
                "Starting DNS proxy on {} with {} upstream server(s)",
                bind_addr,
                upstreams.len()
            ),
        )
        .await;

        // Spawn DNS proxy in background
        tokio::spawn(async move {
            if let Err(e) = proxy.run().await {
                log::error!("DNS proxy error: {}", e);
            }
        });

        // Push tunnel IP as DNS server to clients
        Ok(vec![IpAddress::V4(tunnel_ip)])
    }

    /// Setup DNS proxy for the client if configured
    ///
    /// Returns the DNS proxy task handle if started, or None if not configured/failed.
    async fn setup_client_dns_proxy(
        &self,
        dns_proxy_config: &crate::config::ClientDnsProxyConfig,
        tunnel_ip: Ipv4Addr,
        server_dns_servers: &[IpAddress],
        shutdown_tx: broadcast::Sender<()>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        use hop_dns::{DnsServerSpec, UpstreamStrategy};

        if !dns_proxy_config.enabled {
            return None;
        }

        // Use only server-provided DNS servers
        // This ensures DNS traffic is routed through the VPN tunnel
        if server_dns_servers.is_empty() {
            self.log(
                LogLevel::Info,
                "DNS proxy not started: server did not provide DNS servers".to_string(),
            )
            .await;
            return None;
        }

        let upstream_specs: Vec<DnsServerSpec> = server_dns_servers
            .iter()
            .map(|ip| {
                let addr = match ip {
                    IpAddress::V4(v4) => SocketAddr::new(IpAddr::V4(*v4), 53),
                    IpAddress::V6(v6) => SocketAddr::new(IpAddr::V6(*v6), 53),
                };
                DnsServerSpec::Udp { addr }
            })
            .collect();

        // Use the tunnel IP as bind address for outgoing DNS queries
        // This routes DNS traffic through the VPN tunnel
        let bind_addr = Some(IpAddr::V4(tunnel_ip));

        // Create DNS client
        let dns_client = match DnsClient::with_all_options(
            upstream_specs.clone(),
            1000, // cache size
            UpstreamStrategy::default(),
            dns_proxy_config.filter_ipv6,
            bind_addr,
        ) {
            Ok(client) => Arc::new(client),
            Err(e) => {
                self.log(
                    LogLevel::Error,
                    format!("Failed to create DNS client: {}", e),
                )
                .await;
                return None;
            }
        };

        let listen_addr = SocketAddr::new(IpAddr::V4(tunnel_ip), dns_proxy_config.port);

        // Setup ipset manager if configured (Linux only)
        #[cfg(target_os = "linux")]
        let proxy = {
            use crate::ipset::{IpsetCommandQueue, IpsetManager};
            use hop_dns::ResolvedIps;

            if let Some(ref ipset_name) = dns_proxy_config.ipset {
                let use_nftables = self.config.common.use_nftables;
                match IpsetManager::new(ipset_name, use_nftables) {
                    Ok(ipset_manager) => {
                        let (resolved_tx, mut resolved_rx) =
                            tokio::sync::mpsc::channel::<ResolvedIps>(100);

                        // Create ipset command queue for batched, rate-limited execution
                        let ipset_manager = Arc::new(tokio::sync::Mutex::new(ipset_manager));
                        let ipset_queue = IpsetCommandQueue::with_defaults(ipset_manager);

                        // Spawn task to forward resolved IPs to the queue
                        tokio::spawn(async move {
                            while let Some(resolved) = resolved_rx.recv().await {
                                let ips = resolved.all_ips();
                                if !ips.is_empty() {
                                    ipset_queue.queue_ips(&ips);
                                }
                            }
                        });

                        self.log(
                            LogLevel::Info,
                            format!(
                                "IP set manager initialized for set '{}' with command queue",
                                ipset_name
                            ),
                        )
                        .await;

                        DnsProxy::with_resolved_ips_callback(
                            listen_addr,
                            dns_client,
                            shutdown_tx.subscribe(),
                            resolved_tx,
                        )
                    }
                    Err(e) => {
                        self.log(
                            LogLevel::Warning,
                            format!(
                                "Failed to initialize IP set '{}': {}. DNS proxy will continue without ipset.",
                                ipset_name, e
                            ),
                        )
                        .await;
                        DnsProxy::new(listen_addr, dns_client, shutdown_tx.subscribe())
                    }
                }
            } else {
                DnsProxy::new(listen_addr, dns_client, shutdown_tx.subscribe())
            }
        };

        #[cfg(not(target_os = "linux"))]
        let proxy = DnsProxy::new(listen_addr, dns_client, shutdown_tx.subscribe());

        self.log(
            LogLevel::Info,
            format!(
                "Starting client DNS proxy on {} with {} upstream server(s), filter_ipv6={}",
                listen_addr,
                upstream_specs.len(),
                dns_proxy_config.filter_ipv6
            ),
        )
        .await;

        // Spawn DNS proxy task
        let handle = tokio::spawn(async move {
            if let Err(e) = proxy.run().await {
                log::error!("Client DNS proxy error: {}", e);
            }
        });

        Some(handle)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_server_loop(
        &self,
        tun: Arc<TunDevice>,
        sockets: Vec<Arc<TrackedUdpSocket>>,
        cipher: Cipher,
        pool: Arc<Mutex<Ipv4Pool>>,
        server_config: ServerConfig,
        shutdown_tx: broadcast::Sender<()>,
        shared_stats: SharedStatsRef,
        dns_servers: Vec<IpAddress>,
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

                                    // Encrypt and send via last received socket from the same local address
                                    // This ensures NAT traversal works on multi-homed servers
                                    match cipher_encrypt.encrypt(&packet, 0) {
                                        Ok(encrypted) => {
                                            // Use the socket that last received from this client
                                            // and send from the same local address for NAT traversal
                                            let socket =
                                                &sockets_write[client.last_recv_socket_idx];
                                            let _ = socket
                                                .send_to_from(
                                                    &encrypted,
                                                    client.peer_addr,
                                                    client.last_recv_local_addr,
                                                )
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

        // Wrap DNS servers in Arc for sharing
        let dns_servers = Arc::new(dns_servers);

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
            let dns_servers_clone = dns_servers.clone();

            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 2000];
                loop {
                    match socket_read.recv_from_tracked(&mut buf).await {
                        Ok(recv_result) => {
                            let n = recv_result.len;
                            let peer_addr = recv_result.peer_addr;
                            let local_addr = recv_result.local_addr;

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
                                    local_addr,
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
                                    local_addr,
                                    socket_idx,
                                    &event_handler_udp,
                                    &dns_servers_clone,
                                )
                                .await;
                            } else if flags.is_handshake() && flags.is_ack() {
                                // Handshake confirmation from client
                                let mut sessions = sessions_write.write().await;
                                if let Some(client) = sessions.get_mut(&sid) {
                                    // Update peer address, local address, and socket index for NAT traversal
                                    // (client may send from different source addresses in multi-homed setup)
                                    client.peer_addr = peer_addr;
                                    client.last_recv_socket_idx = socket_idx;
                                    client.last_recv_local_addr = local_addr;
                                    client.last_activity = Instant::now();
                                    if client.session.state == SessionState::Handshake {
                                        if let Err(e) = client.session.complete_handshake_v2(
                                            client.client_addr.ip,
                                            client.client_addr.mask,
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
                                    local_addr,
                                    &event_handler_udp,
                                    &stats_udp,
                                )
                                .await;
                            } else if flags.is_data() {
                                // Data packet - update peer address and socket for NAT traversal
                                let mut sessions = sessions_write.write().await;
                                if let Some(client) = sessions.get_mut(&sid) {
                                    // Update peer address, local address, and socket index for NAT traversal
                                    // (client may send from different source addresses in multi-homed setup)
                                    client.peer_addr = peer_addr;
                                    client.last_recv_socket_idx = socket_idx;
                                    client.last_recv_local_addr = local_addr;
                                    client.last_activity = Instant::now();
                                    if client.session.state == SessionState::Working {
                                        // Write to TUN
                                        if let Err(e) = tun_write.write(&packet.payload).await {
                                            log::error!("TUN write error: {}", e);
                                        }
                                    }
                                }
                            } else if flags.is_probe() && !flags.is_ack() {
                                // Probe request from client - echo back probe response
                                // This allows client to detect blocked paths
                                let sessions = sessions_write.read().await;
                                if sessions.contains_key(&sid) {
                                    // Echo probe response with same probe_id and timestamp
                                    let probe_id = packet.header.seq;
                                    let timestamp = packet.parse_probe_timestamp().unwrap_or(0);
                                    let response = Packet::probe_response(probe_id, sid, timestamp);
                                    if let Ok(encrypted) = cipher_decrypt.encrypt(&response, 0) {
                                        // Reply via same socket for NAT traversal
                                        if let Err(e) = socket_read
                                            .send_to_from(&encrypted, peer_addr, local_addr)
                                            .await
                                        {
                                            log::debug!("Failed to send probe response: {}", e);
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

        let auto_reconnect = client_config.auto_reconnect;
        let reconnect_delay = Duration::from_secs(client_config.reconnect_delay);
        let max_attempts = client_config.max_reconnect_attempts;
        let mut attempt = 0u32;

        loop {
            attempt += 1;
            if max_attempts > 0 && attempt > max_attempts {
                self.log(
                    LogLevel::Error,
                    format!("Max reconnection attempts ({}) reached", max_attempts),
                )
                .await;
                return Err(Error::Connection(
                    "max reconnection attempts reached".to_string(),
                ));
            }

            let result = self
                .run_client_connection(&shutdown_tx, client_config, common_config, attempt)
                .await;

            match result {
                Ok(()) => {
                    // Clean shutdown
                    return Ok(());
                }
                Err(ref e) if e.should_reconnect() && auto_reconnect => {
                    self.set_state(VpnState::Reconnecting).await;
                    self.log(
                        LogLevel::Info,
                        format!(
                            "Connection lost, will reconnect in {} seconds (attempt {}{})",
                            reconnect_delay.as_secs(),
                            attempt,
                            if max_attempts > 0 {
                                format!("/{}", max_attempts)
                            } else {
                                String::new()
                            }
                        ),
                    )
                    .await;

                    // Wait before reconnecting, but check for shutdown
                    let mut shutdown_rx = shutdown_tx.subscribe();
                    tokio::select! {
                        _ = tokio::time::sleep(reconnect_delay) => {
                            // Continue to reconnect
                        }
                        _ = shutdown_rx.recv() => {
                            self.log(LogLevel::Info, "Shutdown requested during reconnect delay").await;
                            self.set_state(VpnState::Disconnected).await;
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    // Non-recoverable error or auto_reconnect disabled
                    self.set_state(VpnState::Disconnected).await;
                    return Err(e);
                }
            }
        }
    }

    /// Run a single client connection attempt
    async fn run_client_connection(
        &self,
        shutdown_tx: &broadcast::Sender<()>,
        client_config: &ClientConfig,
        common_config: &CommonConfig,
        attempt: u32,
    ) -> Result<()> {
        if attempt > 1 {
            self.set_state(VpnState::Reconnecting).await;
            self.log(LogLevel::Info, format!("Reconnection attempt {}", attempt))
                .await;
        } else {
            self.set_state(VpnState::Connecting).await;
        }
        self.log(
            LogLevel::Info,
            format!("Connecting to server: {:?}", client_config.server),
        )
        .await;

        // Configure Windows Firewall to allow VPN traffic
        #[cfg(windows)]
        {
            if let Err(e) = hop_tun::windows::configure_vpn_firewall("Ruhop", true) {
                self.log(
                    LogLevel::Warning,
                    format!("Failed to configure firewall: {}", e),
                )
                .await;
            }
        }

        // Create cipher
        let cipher = create_cipher(common_config);

        // Resolve all server addresses (hosts × port range)
        let server_addrs = client_config.server_addrs()?;
        let server_ips = client_config.resolve_server_ips()?;
        let ipv4_count = server_ips.iter().filter(|ip| ip.is_ipv4()).count();
        let ipv6_count = server_ips.iter().filter(|ip| ip.is_ipv6()).count();
        self.log(
            LogLevel::Info,
            format!(
                "Resolved {} server addresses ({} IPv4 + {} IPv6 hosts × {} ports)",
                server_addrs.len(),
                ipv4_count,
                ipv6_count,
                client_config.port_range[1] - client_config.port_range[0] + 1
            ),
        )
        .await;

        // Get a random address for initial connection
        let initial_addr = client_config
            .random_server_addr(&server_addrs)
            .ok_or_else(|| Error::Config("no server addresses available".into()))?;

        // Create dual-stack UDP socket (supports both IPv4 and IPv6)
        let socket = Arc::new(
            DualStackSocket::new(&server_addrs)
                .await
                .map_err(|e| Error::Connection(format!("failed to bind UDP socket: {}", e)))?,
        );
        if socket.has_ipv4() && socket.has_ipv6() {
            self.log(LogLevel::Info, "Created dual-stack socket (IPv4 + IPv6)")
                .await;
        } else if socket.has_ipv6() {
            self.log(LogLevel::Info, "Created IPv6 socket").await;
        } else {
            self.log(LogLevel::Info, "Created IPv4 socket").await;
        }

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
        let handshake_result = tokio::time::timeout(handshake_timeout, async {
            loop {
                let (n, _) = socket.recv_from(&mut buf).await?;
                let packet = cipher.decrypt(&buf[..n])?;

                if packet.header.flag.is_handshake_ack() && packet.header.sid == sid {
                    // Use v4 parser to get DNS servers along with addresses
                    let (_, response) = packet.parse_handshake_response_v4()?;
                    let primary = response.addresses.primary();
                    session.complete_handshake_v2(primary.ip, primary.mask)?;

                    // Send confirmation to a random address
                    let confirm = Packet::handshake_confirm(sid);
                    let encrypted = cipher.encrypt(&confirm, 0)?;
                    let confirm_addr = server_addrs_clone
                        .choose(&mut rand::rng())
                        .copied()
                        .unwrap_or(initial_addr);
                    socket.send_to(&encrypted, confirm_addr).await?;

                    return Ok::<_, Error>((primary.ip, primary.mask, response.dns_servers));
                }
            }
        })
        .await
        .map_err(|_| Error::Timeout("handshake timeout".to_string()))??;

        let (tunnel_ip, mask, dns_servers) = handshake_result;
        self.log(
            LogLevel::Info,
            format!("Assigned IP: {}/{}", tunnel_ip, mask),
        )
        .await;
        if !dns_servers.is_empty() {
            self.log(
                LogLevel::Info,
                format!(
                    "DNS servers from server: {:?}",
                    dns_servers
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                ),
            )
            .await;
        }

        // Create TUN device with assigned IP
        // The server's TUN IP is the first usable IP in the subnet (network + 1)
        // This is the gateway that all clients use to reach the VPN
        // e.g., for 10.139.0.0/24: server TUN = 10.139.0.1, clients get 10.139.0.2+
        let server_tunnel_ip = match &tunnel_ip {
            IpAddress::V4(ip) => {
                // Calculate network address from client IP and mask
                let ip_u32 = u32::from_be_bytes(ip.octets());
                let mask_bits = 0xFFFFFFFFu32 << (32 - mask);
                let network = ip_u32 & mask_bits;
                // Server TUN IP is network + 1
                Ipv4Addr::from((network + 1).to_be_bytes())
            }
            _ => {
                return Err(Error::Config(
                    "IPv6 not yet supported for client".to_string(),
                ))
            }
        };

        let tunnel_ipv4 = match tunnel_ip {
            IpAddress::V4(ip) => ip,
            _ => {
                return Err(Error::Config(
                    "IPv6 not yet supported for client".to_string(),
                ))
            }
        };

        // On macOS, don't set a name - let the system assign a utun device
        #[allow(unused_mut)] // mut needed on non-macOS platforms
        let mut tun_builder = TunConfig::builder();
        #[cfg(target_os = "macos")]
        {
            if common_config.tun_device.is_some() {
                log::info!(
                    "tun_device config is ignored on macOS (system auto-assigns utun device names)"
                );
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let device_name = common_config.tun_device.as_deref().unwrap_or("ruhop");
            tun_builder = tun_builder.name(device_name);
        }
        let tun_config = tun_builder
            .ipv4_with_dest(tunnel_ipv4, mask, server_tunnel_ip)
            .mtu(common_config.mtu)
            .build()?;

        let tun = TunDevice::create(tun_config).await?;
        let tun_name = tun.name().to_string();
        self.log(LogLevel::Info, format!("Created TUN device: {}", tun_name))
            .await;

        // Setup routes
        let route_manager = RouteManager::new().await?;
        let server_ips = client_config.resolve_server_ips()?;
        let original_gateway = route_manager.get_default_gateway().await?;
        let added_routes = self
            .setup_client_routes(
                &route_manager,
                client_config,
                &tun_name,
                tunnel_ipv4,
                mask,
                server_tunnel_ip,
                &server_ips,
                original_gateway,
                &dns_servers,
            )
            .await?;

        self.set_state(VpnState::Connected).await;

        // Update control state with tunnel IPs and TUN name for status reporting
        {
            let mut ctrl_state = self.control_state.write().await;
            ctrl_state.tunnel_ip = Some(IpAddr::V4(tunnel_ipv4));
            ctrl_state.peer_ip = Some(IpAddr::V4(server_tunnel_ip));
            ctrl_state.tun_name = Some(tun_name.clone());
        }

        self.emit_event(VpnEvent::Connected {
            tunnel_ip: IpAddr::V4(tunnel_ipv4),
            peer_ip: Some(IpAddr::V4(server_tunnel_ip)),
        })
        .await;

        // Run on_connect script if configured
        // Convert IpAddress to IpAddr for script params
        let dns_ips: Vec<IpAddr> = dns_servers
            .iter()
            .map(|ip| match ip {
                IpAddress::V4(v4) => IpAddr::V4(*v4),
                IpAddress::V6(v6) => IpAddr::V6(*v6),
            })
            .collect();
        let script_params =
            ScriptParams::with_dns(IpAddr::V4(tunnel_ipv4), mask, &tun_name, &dns_ips);

        if let Err(e) =
            run_connect_script(client_config.on_connect.as_deref(), &script_params).await
        {
            self.log(LogLevel::Error, format!("on_connect script failed: {}", e))
                .await;
            // Continue anyway - script failure shouldn't prevent VPN from working
        }

        // Start DNS proxy if configured
        let dns_proxy_handle = if let Some(ref dns_proxy_config) = client_config.dns_proxy {
            self.setup_client_dns_proxy(
                dns_proxy_config,
                tunnel_ipv4,
                &dns_servers,
                shutdown_tx.clone(),
            )
            .await
        } else {
            None
        };

        // Run client main loop
        let result = self
            .run_client_loop(
                Arc::new(tun),
                socket,
                cipher,
                session,
                server_addrs,
                shutdown_tx.clone(),
                self.shared_stats.clone(),
            )
            .await;

        // Cleanup DNS proxy
        if let Some(handle) = dns_proxy_handle {
            handle.abort();
        }

        // Run on_disconnect script if configured
        run_disconnect_script(client_config.on_disconnect.as_deref(), &script_params).await;

        // Cleanup routes
        self.cleanup_client_routes(
            &route_manager,
            &added_routes,
            client_config.mss_fix,
            &tun_name,
        )
        .await;

        result
    }

    /// Setup client routes and return the list of successfully added routes for cleanup
    #[allow(clippy::too_many_arguments)]
    async fn setup_client_routes(
        &self,
        route_manager: &RouteManager,
        client_config: &ClientConfig,
        tun_name: &str,
        tunnel_ip: Ipv4Addr,
        prefix_len: u8,
        tun_gateway: Ipv4Addr,
        server_ips: &[IpAddr],
        original_gateway: Option<IpAddr>,
        dns_servers: &[IpAddress],
    ) -> Result<Vec<Route>> {
        let mut added_routes: Vec<Route> = Vec::new();

        // Add routes for the tunnel subnet
        let tunnel_net = ipnet::Ipv4Net::new(tunnel_ip, prefix_len)
            .map_err(|e| Error::Config(format!("Invalid tunnel network: {}", e)))?
            .trunc(); // Get the network address

        #[cfg(target_os = "linux")]
        {
            // On Linux with point-to-point TUN interfaces, we need two routes:
            // 1. A host route to the peer (gateway) IP directly via the interface
            // 2. A subnet route via the peer IP as gateway

            // Route 1: Host route to peer (gateway) - makes the gateway reachable
            let peer_route = Route::interface_route(
                ipnet::IpNet::V4(ipnet::Ipv4Net::new(tun_gateway, 32).unwrap()),
                tun_name,
            );
            if let Err(e) = route_manager.add(&peer_route).await {
                self.log(
                    LogLevel::Warning,
                    format!("Failed to add peer route: {}", e),
                )
                .await;
            } else {
                self.log(
                    LogLevel::Info,
                    format!("Added route: {}/32 dev {}", tun_gateway, tun_name),
                )
                .await;
                added_routes.push(peer_route);
            }

            // Route 2: Subnet route via the gateway
            let subnet_route = Route::ipv4(
                tunnel_net.addr(),
                tunnel_net.prefix_len(),
                Some(tun_gateway),
            )
            .map_err(|e| Error::Config(format!("Invalid tunnel route: {}", e)))?
            .with_interface(tun_name);
            if let Err(e) = route_manager.add(&subnet_route).await {
                self.log(
                    LogLevel::Warning,
                    format!("Failed to add tunnel subnet route: {}", e),
                )
                .await;
            } else {
                self.log(
                    LogLevel::Info,
                    format!(
                        "Added route: {} via {} dev {}",
                        tunnel_net, tun_gateway, tun_name
                    ),
                )
                .await;
                added_routes.push(subnet_route);
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // On other platforms, use a simple interface route
            let tunnel_route = Route::interface_route(ipnet::IpNet::V4(tunnel_net), tun_name);
            if let Err(e) = route_manager.add(&tunnel_route).await {
                self.log(
                    LogLevel::Warning,
                    format!("Failed to add tunnel subnet route: {}", e),
                )
                .await;
            } else {
                self.log(
                    LogLevel::Info,
                    format!("Added route: {} dev {}", tunnel_net, tun_name),
                )
                .await;
                added_routes.push(tunnel_route);
            }
        }

        if client_config.route_all_traffic {
            // When routing all traffic through VPN, we need to:
            // 1. Add routes for server IPs via original gateway (to keep VPN connection working)
            // 2. Add catch-all routes (0.0.0.0/1 and 128.0.0.0/1) via TUN

            // Add routes for server IPs to use the original gateway
            if let Some(orig_gw) = original_gateway {
                for server_ip in server_ips {
                    match server_ip {
                        IpAddr::V4(ip) => {
                            if let IpAddr::V4(gw) = orig_gw {
                                if let Ok(route) = Route::ipv4(*ip, 32, Some(gw)) {
                                    if let Err(e) = route_manager.add(&route).await {
                                        self.log(
                                            LogLevel::Warning,
                                            format!("Failed to add server route for {}: {}", ip, e),
                                        )
                                        .await;
                                    } else {
                                        self.log(
                                            LogLevel::Info,
                                            format!("Added route: {}/32 via {}", ip, gw),
                                        )
                                        .await;
                                        added_routes.push(route);
                                    }
                                }
                            }
                        }
                        IpAddr::V6(ip) => {
                            if let IpAddr::V6(gw) = orig_gw {
                                if let Ok(route) = Route::ipv6(*ip, 128, Some(gw)) {
                                    if let Err(e) = route_manager.add(&route).await {
                                        self.log(
                                            LogLevel::Warning,
                                            format!("Failed to add server route for {}: {}", ip, e),
                                        )
                                        .await;
                                    } else {
                                        self.log(
                                            LogLevel::Info,
                                            format!("Added route: {}/128 via {}", ip, gw),
                                        )
                                        .await;
                                        added_routes.push(route);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                self.log(LogLevel::Warning, "No default gateway found, server routes not added - VPN traffic may be disrupted").await;
            }

            // Route all traffic through VPN
            // Split into two /1 routes to override default without removing it
            let route1 = Route::ipv4(Ipv4Addr::new(0, 0, 0, 0), 1, Some(tun_gateway))?
                .with_interface(tun_name);
            let route2 = Route::ipv4(Ipv4Addr::new(128, 0, 0, 0), 1, Some(tun_gateway))?
                .with_interface(tun_name);

            route_manager.add(&route1).await?;
            self.log(
                LogLevel::Info,
                format!(
                    "Added route: 0.0.0.0/1 via {} dev {}",
                    tun_gateway, tun_name
                ),
            )
            .await;
            added_routes.push(route1);

            route_manager.add(&route2).await?;
            self.log(
                LogLevel::Info,
                format!(
                    "Added route: 128.0.0.0/1 via {} dev {}",
                    tun_gateway, tun_name
                ),
            )
            .await;
            added_routes.push(route2);
        } else if !dns_servers.is_empty() {
            // When route_all_traffic is disabled, route DNS server traffic through VPN tunnel
            // so that the DNS proxy can forward queries to server-provided DNS servers.
            for dns_ip in dns_servers {
                match dns_ip {
                    IpAddress::V4(ip) => {
                        if let Ok(route) = Route::ipv4(*ip, 32, Some(tun_gateway)) {
                            let route = route.with_interface(tun_name);
                            if let Err(e) = route_manager.add(&route).await {
                                self.log(
                                    LogLevel::Warning,
                                    format!("Failed to add DNS route for {}: {}", ip, e),
                                )
                                .await;
                            } else {
                                self.log(
                                    LogLevel::Info,
                                    format!(
                                        "Added DNS route: {}/32 via {} dev {}",
                                        ip, tun_gateway, tun_name
                                    ),
                                )
                                .await;
                                added_routes.push(route);
                            }
                        }
                    }
                    IpAddress::V6(ip) => {
                        self.log(
                            LogLevel::Debug,
                            format!("Skipping IPv6 DNS route for {}", ip),
                        )
                        .await;
                    }
                }
            }
        }

        // Setup MSS clamping if enabled (Linux only)
        #[cfg(target_os = "linux")]
        if client_config.mss_fix {
            self.setup_mss_clamping(tun_name).await;
        }

        Ok(added_routes)
    }

    /// Setup MSS clamping for TCP traffic through the TUN interface (Linux only)
    ///
    /// This adds firewall mangle rules to clamp TCP MSS to PMTU, which prevents
    /// fragmentation issues when the VPN client acts as a NAT gateway.
    /// Uses the configured firewall backend (nftables or iptables).
    #[cfg(target_os = "linux")]
    async fn setup_mss_clamping(&self, tun_name: &str) {
        use hop_tun::FirewallBackend;

        let use_nftables = self.config.common.use_nftables;
        match FirewallBackend::select(use_nftables) {
            Ok(FirewallBackend::Nftables) => self.setup_mss_clamping_nftables(tun_name).await,
            Ok(FirewallBackend::Iptables) => self.setup_mss_clamping_iptables(tun_name).await,
            Err(e) => {
                self.log(
                    LogLevel::Error,
                    format!("Failed to setup MSS clamping: {}", e),
                )
                .await;
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn setup_mss_clamping_nftables(&self, tun_name: &str) {
        use std::io::Write;
        use std::process::Command;

        const NFT_MSS_TABLE: &str = "ruhop_mss";

        // Build nftables script for MSS clamping
        let nft_script = format!(
            r#"
table ip {table} {{
    chain forward {{
        type filter hook forward priority mangle; policy accept;
        oifname "{tun}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
    }}
}}
"#,
            table = NFT_MSS_TABLE,
            tun = tun_name,
        );

        // First, delete existing table if present (ignore errors)
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", NFT_MSS_TABLE])
            .output();

        // Apply the new ruleset
        let result = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(nft_script.as_bytes())?;
                }
                child.wait_with_output()
            });

        match result {
            Ok(output) if output.status.success() => {
                self.log(
                    LogLevel::Info,
                    format!("Added MSS clamping rule for {} (nftables)", tun_name),
                )
                .await;
            }
            Ok(output) => {
                self.log(
                    LogLevel::Warning,
                    format!(
                        "Failed to add MSS clamping rule (nftables): {}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                )
                .await;
            }
            Err(e) => {
                self.log(
                    LogLevel::Warning,
                    format!("Failed to run nft for MSS clamping: {}", e),
                )
                .await;
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn setup_mss_clamping_iptables(&self, tun_name: &str) {
        use std::process::Command;

        // Add MSS clamping rule for outbound TCP SYN packets
        let result = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-A",
                "FORWARD",
                "-o",
                tun_name,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                self.log(
                    LogLevel::Info,
                    format!("Added MSS clamping rule for {} (iptables)", tun_name),
                )
                .await;
            }
            Ok(output) => {
                self.log(
                    LogLevel::Warning,
                    format!(
                        "Failed to add MSS clamping rule (iptables): {}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                )
                .await;
            }
            Err(e) => {
                self.log(
                    LogLevel::Warning,
                    format!("Failed to run iptables for MSS clamping: {}", e),
                )
                .await;
            }
        }
    }

    /// Remove MSS clamping rules (Linux only)
    ///
    /// Cleans up both nftables and iptables rules to ensure thorough cleanup
    /// regardless of which backend was used.
    #[cfg(target_os = "linux")]
    fn cleanup_mss_clamping(tun_name: &str) {
        // Clean up both backends to ensure thorough cleanup
        Self::cleanup_mss_clamping_nftables();
        Self::cleanup_mss_clamping_iptables(tun_name);
    }

    #[cfg(target_os = "linux")]
    fn cleanup_mss_clamping_nftables() {
        use std::process::Command;

        const NFT_MSS_TABLE: &str = "ruhop_mss";

        // Delete the MSS clamping table
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", NFT_MSS_TABLE])
            .output();
    }

    #[cfg(target_os = "linux")]
    fn cleanup_mss_clamping_iptables(tun_name: &str) {
        use std::process::Command;

        // Remove MSS clamping rule
        let _ = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-D",
                "FORWARD",
                "-o",
                tun_name,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ])
            .output();
    }

    /// Cleanup all routes that were added during connection
    async fn cleanup_client_routes(
        &self,
        route_manager: &RouteManager,
        routes: &[Route],
        mss_fix: bool,
        tun_name: &str,
    ) {
        // Delete all routes that were successfully added
        for route in routes {
            if let Err(e) = route_manager.delete(route).await {
                self.log(
                    LogLevel::Debug,
                    format!("Failed to delete route {}: {}", route, e),
                )
                .await;
            } else {
                self.log(LogLevel::Debug, format!("Deleted route: {}", route))
                    .await;
            }
        }

        // Cleanup MSS clamping if it was enabled (Linux only)
        #[cfg(target_os = "linux")]
        if mss_fix {
            Self::cleanup_mss_clamping(tun_name);
        }

        // Suppress unused variable warning on non-Linux
        #[cfg(not(target_os = "linux"))]
        let _ = (mss_fix, tun_name);
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_client_loop(
        &self,
        tun: Arc<TunDevice>,
        socket: Arc<DualStackSocket>,
        cipher: Cipher,
        session: Session,
        server_addrs: Vec<SocketAddr>,
        shutdown_tx: broadcast::Sender<()>,
        shared_stats: SharedStatsRef,
    ) -> Result<()> {
        use crate::addr_stats::AddrStatsTracker;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut shutdown_rx = shutdown_tx.subscribe();
        let sid = session.id.value();

        // Get probe config (if enabled)
        let probe_config = self.config.client.as_ref().and_then(|c| c.probe.as_ref());

        // Sequence number counter
        let seq = Arc::new(std::sync::atomic::AtomicU32::new(0));

        // Server addresses for port hopping
        let server_addrs = Arc::new(server_addrs.clone());

        // Address statistics tracker for loss detection (only if probing enabled)
        let addr_tracker: Option<Arc<RwLock<AddrStatsTracker>>> = if let Some(cfg) = probe_config {
            let tracker = Arc::new(RwLock::new(AddrStatsTracker::new(
                server_addrs.to_vec(),
                Duration::from_secs(cfg.interval),
                cfg.threshold,
                Duration::from_secs(cfg.blacklist_duration),
                cfg.min_probes,
            )));

            // Set up blacklist callback for events and control state updates
            let event_handler_bl = self.event_handler.clone();
            let control_state_bl = self.control_state.clone();
            let blacklist_duration = cfg.blacklist_duration;
            {
                let mut t = tracker.write().await;
                t.set_blacklist_callback(Box::new(move |addr, is_blacklisted, loss_rate| {
                    let handler = event_handler_bl.clone();
                    let ctrl_state = control_state_bl.clone();
                    let event = if is_blacklisted {
                        VpnEvent::AddressBlacklisted {
                            addr,
                            loss_rate,
                            duration_secs: blacklist_duration,
                        }
                    } else {
                        VpnEvent::AddressRecovered { addr }
                    };
                    // Fire-and-forget event emission and control state update
                    tokio::spawn(async move {
                        handler.on_event(event).await;
                        // Update control state blacklist
                        let mut state = ctrl_state.write().await;
                        if is_blacklisted {
                            // Add to blacklist if not already present
                            let addr_str = addr.to_string();
                            if !state
                                .blacklisted_endpoints
                                .iter()
                                .any(|e| e.addr == addr_str)
                            {
                                state.blacklisted_endpoints.push(BlacklistedEndpoint {
                                    addr: addr_str,
                                    loss_rate,
                                });
                            }
                        } else {
                            // Remove from blacklist
                            let addr_str = addr.to_string();
                            state.blacklisted_endpoints.retain(|e| e.addr != addr_str);
                        }
                    });
                }));
            }

            log::info!(
                "Path loss detection enabled: interval={}s, threshold={:.0}%, blacklist={}s",
                cfg.interval,
                cfg.threshold * 100.0,
                cfg.blacklist_duration
            );

            Some(tracker)
        } else {
            None
        };

        // Spawn TUN -> UDP task
        let tun_read = tun.clone();
        let socket_write = socket.clone();
        let cipher_encrypt = cipher.clone();
        let stats_tun = shared_stats.clone();
        let seq_tun = seq.clone();
        let server_addrs_tun = server_addrs.clone();
        let addr_tracker_tun = addr_tracker.clone();

        let mut tun_to_udp = tokio::spawn(async move {
            let mut buf = vec![0u8; 2000];
            loop {
                match tun_read.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let seq_num = seq_tun.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let packet = Packet::data(seq_num, sid, buf[..n].to_vec());

                        match cipher_encrypt.encrypt(&packet, 0) {
                            Ok(encrypted) => {
                                // Port hopping: prefer available (non-blacklisted) addresses if probing enabled
                                let target_addr = if let Some(ref tracker) = addr_tracker_tun {
                                    let available = tracker.read().await.available_addrs();
                                    if available.is_empty() {
                                        // Fallback to any address if all are blacklisted
                                        server_addrs_tun
                                            .choose(&mut rand::rng())
                                            .copied()
                                            .unwrap_or(server_addrs_tun[0])
                                    } else {
                                        available
                                            .choose(&mut rand::rng())
                                            .copied()
                                            .unwrap_or(available[0])
                                    }
                                } else {
                                    // No probing - use random address
                                    server_addrs_tun
                                        .choose(&mut rand::rng())
                                        .copied()
                                        .unwrap_or(server_addrs_tun[0])
                                };

                                if let Err(e) = socket_write.send_to(&encrypted, target_addr).await
                                {
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

        // Track last heartbeat response for connection loss detection
        let last_heartbeat_response = Arc::new(RwLock::new(Instant::now()));

        // Spawn UDP -> TUN task
        let tun_write = tun.clone();
        let socket_read = socket.clone();
        let cipher_decrypt = cipher.clone();
        let stats_udp = shared_stats.clone();
        let addr_tracker_udp = addr_tracker.clone();
        let last_hb_udp = last_heartbeat_response.clone();

        let mut udp_to_tun = tokio::spawn(async move {
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
                            // Data packet also counts as server being alive
                            *last_hb_udp.write().await = Instant::now();
                            if let Err(e) = tun_write.write(&packet.payload).await {
                                log::error!("TUN write error: {}", e);
                            }
                        } else if packet.header.flag.is_push() && packet.header.flag.is_ack() {
                            // Heartbeat response - connection is alive
                            *last_hb_udp.write().await = Instant::now();
                            log::debug!("Received heartbeat response");
                        } else if packet.header.flag.is_probe_ack() {
                            // Probe response - record for loss detection (only if probing enabled)
                            if let Some(ref tracker) = addr_tracker_udp {
                                let probe_id = packet.header.seq;
                                let now_ms = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis()
                                    as u64;
                                let sent_ms = packet.parse_probe_timestamp().unwrap_or(now_ms);
                                let rtt = Duration::from_millis(now_ms.saturating_sub(sent_ms));

                                let mut t = tracker.write().await;
                                t.record_probe_received(probe_id, rtt);
                                t.update_all_blacklist_status();
                                log::debug!(
                                    "Probe response: id={}, rtt={}ms",
                                    probe_id,
                                    rtt.as_millis()
                                );
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

        // Spawn probe task for loss detection (only if probing enabled)
        let probe_task = if let Some(tracker) = addr_tracker.clone() {
            let socket_probe = socket.clone();
            let cipher_probe = cipher.clone();

            Some(tokio::spawn(async move {
                let mut probe_id: u32 = 0;
                // Check for probe targets every 500ms
                // The tracker internally manages per-address intervals
                let mut ticker = interval(Duration::from_millis(500));

                loop {
                    ticker.tick().await;

                    // Get next address that needs probing
                    let target = {
                        let mut t = tracker.write().await;
                        t.next_probe_target()
                    };

                    if let Some(target_addr) = target {
                        let timestamp_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;

                        let probe = Packet::probe_request(probe_id, sid, timestamp_ms);

                        // Record that we sent a probe
                        {
                            let mut t = tracker.write().await;
                            t.record_probe_sent(target_addr, probe_id);
                        }

                        if let Ok(encrypted) = cipher_probe.encrypt(&probe, 0) {
                            // Send to specific target (not random)
                            let _ = socket_probe.send_to(&encrypted, target_addr).await;
                            log::trace!("Sent probe {} to {}", probe_id, target_addr);
                        }

                        probe_id = probe_id.wrapping_add(1);
                    }

                    // Periodically update blacklist status for timeouts
                    {
                        let mut t = tracker.write().await;
                        t.update_all_blacklist_status();
                    }
                }
            }))
        } else {
            None
        };

        // Spawn heartbeat timeout monitor task
        let heartbeat_timeout = Duration::from_secs(heartbeat_interval.as_secs() * 3);
        let last_hb_monitor = last_heartbeat_response.clone();
        let (timeout_tx, mut timeout_rx) = tokio::sync::mpsc::channel::<()>(1);

        let timeout_monitor = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(5)); // Check every 5 seconds
            loop {
                ticker.tick().await;
                let last = *last_hb_monitor.read().await;
                if last.elapsed() > heartbeat_timeout {
                    log::warn!(
                        "Heartbeat timeout: no response for {:?} (threshold: {:?})",
                        last.elapsed(),
                        heartbeat_timeout
                    );
                    let _ = timeout_tx.send(()).await;
                    break;
                }
            }
        });

        // Get abort handles so we can abort tasks later
        let tun_to_udp_abort = tun_to_udp.abort_handle();
        let udp_to_tun_abort = udp_to_tun.abort_handle();
        let heartbeat_abort = heartbeat.abort_handle();
        let timeout_monitor_abort = timeout_monitor.abort_handle();
        let probe_abort = probe_task.as_ref().map(|t| t.abort_handle());

        // Wait for shutdown, error, or heartbeat timeout
        let connection_lost;
        tokio::select! {
            _ = shutdown_rx.recv() => {
                log::info!("Client shutdown requested");
                connection_lost = false;

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
            _ = timeout_rx.recv() => {
                log::error!("Connection lost: heartbeat timeout");
                connection_lost = true;
            }
            _ = &mut tun_to_udp => {
                log::error!("TUN to UDP task ended unexpectedly");
                connection_lost = true;
            }
            _ = &mut udp_to_tun => {
                log::error!("UDP to TUN task ended unexpectedly");
                connection_lost = true;
            }
        }

        // Abort all tasks to release Arc<TunDevice> references
        tun_to_udp_abort.abort();
        udp_to_tun_abort.abort();
        heartbeat_abort.abort();
        timeout_monitor_abort.abort();
        if let Some(abort) = probe_abort {
            abort.abort();
        }

        // Wait for tasks to complete (they are now aborted)
        let _ = tun_to_udp.await;
        let _ = udp_to_tun.await;
        let _ = heartbeat.await;
        let _ = timeout_monitor.await;
        if let Some(task) = probe_task {
            let _ = task.await;
        }

        if connection_lost {
            self.emit_event(VpnEvent::Disconnected {
                reason: "Connection lost".to_string(),
            })
            .await;
            return Err(Error::ConnectionLost("heartbeat timeout".to_string()));
        }

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

    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
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
    local_addr: SocketAddr,
    socket_idx: usize,
    _event_handler: &Arc<dyn EventHandler>,
    shared_stats: &SharedStatsRef,
) {
    let mut sessions_lock = sessions.write().await;

    // Check if session already exists
    if let Some(client) = sessions_lock.get_mut(&sid) {
        // Update peer address, local address, and socket index for NAT traversal
        // (client may send from different source addresses in multi-homed setup)
        client.peer_addr = peer_addr;
        client.last_recv_socket_idx = socket_idx;
        client.last_recv_local_addr = local_addr;
        client.last_activity = Instant::now();
        return;
    }

    // Check max clients
    if sessions_lock.len() >= server_config.max_clients {
        log::warn!("Max clients reached, rejecting {}", peer_addr);
        return;
    }

    // Allocate IP address
    let client_addr = match pool.lock().await.allocate() {
        Ok(addr) => addr,
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
            client_addr,
            last_recv_socket_idx: socket_idx,
            last_recv_local_addr: local_addr,
        },
    );

    // Update active sessions count
    shared_stats.set_active_sessions(sessions_lock.len());

    // Add IP mapping
    if let IpAddress::V4(ip) = client_addr.ip {
        ip_to_session.write().await.insert(ip, sid);
    }

    log::info!(
        "New client knock from {} to local {}: sid={}, assigned={}",
        peer_addr,
        local_addr,
        SessionId::new(sid),
        client_addr.ip
    );
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_handshake(
    sessions: &RwLock<HashMap<u32, ClientSession>>,
    ip_to_session: &RwLock<HashMap<Ipv4Addr, u32>>,
    pool: &Mutex<Ipv4Pool>,
    socket: &TrackedUdpSocket,
    cipher: &Cipher,
    server_config: &ServerConfig,
    sid: u32,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    socket_idx: usize,
    event_handler: &Arc<dyn EventHandler>,
    dns_servers: &[IpAddress],
) {
    let mut sessions_lock = sessions.write().await;

    // Get or create session
    let client = if let Some(c) = sessions_lock.get_mut(&sid) {
        // Update peer address, local address, and socket index for NAT traversal
        // (client may send from different source addresses in multi-homed setup)
        c.peer_addr = peer_addr;
        c.last_recv_socket_idx = socket_idx;
        c.last_recv_local_addr = local_addr;
        c
    } else {
        // Session doesn't exist - might have been a knock we missed
        // Check max clients
        if sessions_lock.len() >= server_config.max_clients {
            log::warn!(
                "Max clients reached, rejecting handshake from {}",
                peer_addr
            );
            return;
        }

        // Allocate IP
        let client_addr = match pool.lock().await.allocate() {
            Ok(addr) => addr,
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
                client_addr,
                last_recv_socket_idx: socket_idx,
                last_recv_local_addr: local_addr,
            },
        );

        if let IpAddress::V4(ip) = client_addr.ip {
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

    // Send handshake response with assigned IP and DNS servers (v4 protocol)
    let addresses = AssignedAddresses::single(client.client_addr.ip, client.client_addr.mask);
    let response = Packet::handshake_response_v4(sid, addresses, dns_servers.to_vec());

    match cipher.encrypt(&response, 0) {
        Ok(encrypted) => {
            // Send from the same local address for proper NAT traversal
            if let Err(e) = socket.send_to_from(&encrypted, peer_addr, local_addr).await {
                log::error!("Failed to send handshake response: {}", e);
            } else {
                log::info!(
                    "Sent handshake response to {} from local {}: ip={}",
                    peer_addr,
                    local_addr,
                    client.client_addr.ip
                );

                event_handler
                    .on_event(VpnEvent::ClientConnected {
                        session_id: sid,
                        assigned_ip: match client.client_addr.ip {
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
    socket: &TrackedUdpSocket,
    cipher: &Cipher,
    sid: u32,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    event_handler: &Arc<dyn EventHandler>,
    shared_stats: &SharedStatsRef,
) {
    let mut sessions_lock = sessions.write().await;

    if let Some(client) = sessions_lock.remove(&sid) {
        // Update active sessions count
        shared_stats.set_active_sessions(sessions_lock.len());

        // Send FIN ACK from the same local address for NAT traversal
        let fin_ack = Packet::finish_ack(sid);
        if let Ok(encrypted) = cipher.encrypt(&fin_ack, 0) {
            let _ = socket.send_to_from(&encrypted, peer_addr, local_addr).await;
        }

        // Remove IP mapping
        if let IpAddress::V4(ip) = client.client_addr.ip {
            ip_to_session.write().await.remove(&ip);
        }

        // Release IP back to pool
        pool.lock().await.release(&client.client_addr.ip);

        log::info!(
            "Client {} disconnected: {}",
            SessionId::new(sid),
            client.client_addr.ip
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
