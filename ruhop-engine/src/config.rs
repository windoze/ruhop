//! Configuration types for the VPN engine

use rand::prelude::IndexedRandom;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;

use crate::error::{Error, Result};
use hop_dns::{parse_dns_server, DnsServerSpec};

/// Main configuration structure
///
/// The configuration file uses TOML format and contains sections
/// for both server and client modes. Only the relevant section
/// is used based on the mode the application is running in.
///
/// # Example Configuration
///
/// ```toml
/// # Shared settings
/// [common]
/// key = "my-secret-key"
/// mtu = 1400
/// log_level = "info"
///
/// # Server-specific settings
/// [server]
/// listen = "0.0.0.0"
/// port_range = [4096, 4196]
/// tunnel_ip = "10.0.0.1"
/// tunnel_network = "10.0.0.0/24"
/// dns_proxy = true  # Enable DNS proxy on tunnel IP
///
/// # Client-specific settings
/// [client]
/// # Single server host:
/// server = "vpn.example.com"
/// # Or multiple hosts: server = ["vpn1.example.com", "vpn2.example.com"]
/// port_range = [4096, 4196]
/// tunnel_ip = "10.0.0.2"  # Optional, assigned by server if not set
/// route_all_traffic = true
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Common settings shared between server and client
    #[serde(default)]
    pub common: CommonConfig,

    /// Server-specific configuration
    pub server: Option<ServerConfig>,

    /// Client-specific configuration
    pub client: Option<ClientConfig>,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Parse configuration from a TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        let config: Config = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.common.key.is_empty() {
            return Err(Error::Config("key is required".into()));
        }

        if self.common.mtu < 576 {
            return Err(Error::Config(format!(
                "MTU {} is too small (minimum 576)",
                self.common.mtu
            )));
        }

        if let Some(ref server) = self.server {
            server.validate()?;
        }

        if let Some(ref client) = self.client {
            client.validate()?;
        }

        Ok(())
    }

    /// Get the server configuration, or error if not present
    pub fn server_config(&self) -> Result<&ServerConfig> {
        self.server
            .as_ref()
            .ok_or_else(|| Error::Config("server configuration is required".into()))
    }

    /// Get the client configuration, or error if not present
    pub fn client_config(&self) -> Result<&ClientConfig> {
        self.client
            .as_ref()
            .ok_or_else(|| Error::Config("client configuration is required".into()))
    }

    /// Generate a sample configuration
    pub fn sample() -> String {
        r#"# Ruhop VPN Configuration

# Shared settings used by both server and client
[common]
# Pre-shared key for encryption (required)
key = "your-secret-key-here"

# MTU for the tunnel interface (default: 1400)
mtu = 1400

# Log level: "error", "warn", "info", "debug", "trace"
log_level = "info"

# Log file directory (optional)
# When set, logs are written to files in this directory with time-based rolling.
# If not set, logs are written to stdout only.
# Log files are named: ruhop.YYYY-MM-DD (daily), ruhop.YYYY-MM-DD-HH (hourly), etc.
# log_file = "/var/log/ruhop"

# Log rotation period: "hourly", "daily", "never" (default: "daily")
# Only used when log_file is set.
# log_rotation = "daily"

# Firewall backend selection (Linux only)
# Explicitly choose between nftables and iptables/ipset:
# - true: Use nftables (modern, preferred)
# - false: Use iptables/ipset (legacy)
# If not set, auto-detects (tries nftables first, falls back to iptables)
# NOTE: Auto-detection may break some tools as nftables and iptables rules are *not* interchangeable.
# use_nftables = true

# Enable packet obfuscation (default: false)
obfuscation = false

# Heartbeat interval in seconds (default: 30)
heartbeat_interval = 30

# TUN device name (optional)
# On Linux/Windows: defaults to "ruhop" if not specified
# On macOS: ignored (system auto-assigns utun device names)
# Set this to run multiple ruhop instances on the same machine
# tun_device = "ruhop0"

# Server configuration (used when running as server)
[server]
# IP address to listen on (binds to all ports in port_range)
listen = "0.0.0.0"

# Port range for port hopping [start, end]
# Server listens on ALL ports in this range simultaneously
port_range = [4096, 4196]

# Tunnel network in CIDR notation (for IP allocation)
tunnel_network = "10.0.0.0/24"

# Server's tunnel IP address (optional, defaults to first IP in tunnel_network)
# tunnel_ip = "10.0.0.1"

# Enable DNS proxy on the server (default: false)
# When enabled, runs a DNS proxy on the tunnel IP and pushes it to clients.
# Clients with dns_proxy enabled will forward their DNS queries through this proxy.
# dns_proxy = true

# Upstream DNS servers for the DNS proxy (only used when dns_proxy = true)
# Supports: "IP[:port][/udp|tcp]", "https://...", "tls://..."
# If not specified, defaults to ["8.8.8.8", "1.1.1.1"]
# dns_servers = ["8.8.8.8", "https://cloudflare-dns.com/dns-query"]

# Maximum number of clients (default: 100)
max_clients = 100

# Enable NAT/masquerading for client traffic
enable_nat = true

# Outbound interface for NAT (auto-detected if not set)
# nat_interface = "eth0"

# Client configuration (used when running as client)
[client]
# Server host(s) - hostname or IP, no port (required)
# Can be a single host:
server = "vpn.example.com"
# Or multiple hosts for multi-homed servers:
# server = ["vpn1.example.com", "vpn2.example.com", "1.2.3.4"]

# Port range for port hopping (should match server)
# All ports in this range will be used for sending packets
port_range = [4096, 4196]

# Specific tunnel IP to request (optional, assigned by server if not set)
# tunnel_ip = "10.0.0.2"

# Route all traffic through the VPN (default: true)
route_all_traffic = true

# Routes to exclude from the VPN (bypassed)
# excluded_routes = ["192.168.1.0/24"]

# DNS servers to use when connected
# dns = ["8.8.8.8"]

# Reconnect automatically on connection loss
auto_reconnect = true

# Maximum reconnect attempts (0 = unlimited)
max_reconnect_attempts = 0

# Reconnect delay in seconds
reconnect_delay = 5

# Script to run when VPN connects (optional)
# Arguments: <local_ip> <netmask> <tun_device> <dns_servers>
# on_connect = "/path/to/connect-script.sh"

# Script to run when VPN disconnects (optional)
# Arguments: <local_ip> <netmask> <tun_device> <dns_servers>
# on_disconnect = "/path/to/disconnect-script.sh"

# Enable MSS clamping for TCP traffic (Linux only, default: false)
# Useful when the VPN client acts as a NAT gateway for other devices
# mss_fix = true

# Path loss detection (optional)
# When enabled, the client probes each server address to detect blocked paths
# Addresses with high packet loss are temporarily blacklisted
# [client.probe]
# interval = 10            # Seconds between probes to each address
# threshold = 0.5          # Loss rate threshold for blacklisting (0.0-1.0)
# blacklist_duration = 300 # Seconds to keep address blacklisted
# min_probes = 3           # Minimum probes before blacklist decision

# Client-side DNS proxy (optional)
# Runs a DNS proxy on the tunnel IP to forward DNS queries through the VPN.
# The proxy uses DNS servers provided by the VPN server as upstreams.
# If the server does not provide DNS servers, the proxy will not start.
# [client.dns_proxy]
# enabled = true
# port = 53                # Listen port (default: 53)
# filter_ipv6 = false      # Filter AAAA records (default: false)
# ipset = "vpn_resolved"   # Linux only: add resolved IPs to ipset
"#
        .to_string()
    }
}


/// Common configuration shared between server and client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonConfig {
    /// Pre-shared key for encryption
    #[serde(default)]
    pub key: String,

    /// MTU for the tunnel interface
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Enable packet obfuscation
    #[serde(default)]
    pub obfuscation: bool,

    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// Path for the control socket (for `ruhop status` command)
    #[serde(default)]
    pub control_socket: Option<String>,

    /// TUN device name (optional)
    ///
    /// On Linux/Windows: defaults to "ruhop" if not specified.
    /// On macOS: ignored (system auto-assigns utun device names).
    ///
    /// Set this to run multiple ruhop instances on the same machine.
    #[serde(default)]
    pub tun_device: Option<String>,

    /// Log file path (optional)
    ///
    /// When set, logs are written to this file with time-based rolling.
    /// If not set, logs are written to stdout only.
    ///
    /// The path should be a directory where log files will be created.
    /// Log files are named with the rotation period suffix (e.g., ruhop.2024-01-15).
    #[serde(default)]
    pub log_file: Option<String>,

    /// Log rotation period (default: "daily")
    ///
    /// How often to rotate log files. Options: "hourly", "daily", "never".
    /// Only used when `log_file` is set.
    #[serde(default = "default_log_rotation")]
    pub log_rotation: String,

    /// Firewall backend selection (Linux only)
    ///
    /// Explicitly select the firewall backend for NAT, MSS clamping, and IP sets:
    /// - `true`: Use nftables (modern, preferred)
    /// - `false`: Use iptables/ipset (legacy)
    /// - Not set (default): Auto-detect (tries nftables first, falls back to iptables)
    ///
    /// This option is ignored on non-Linux platforms.
    #[serde(default)]
    pub use_nftables: Option<bool>,
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            key: String::new(),
            mtu: default_mtu(),
            log_level: default_log_level(),
            obfuscation: false,
            heartbeat_interval: default_heartbeat_interval(),
            control_socket: None,
            tun_device: None,
            log_file: None,
            log_rotation: default_log_rotation(),
            use_nftables: None,
        }
    }
}


/// Server-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// IP address to listen on (e.g., "0.0.0.0" for all interfaces)
    ///
    /// Note: Port is not specified here - use `port_range` instead.
    /// The server will bind to all ports in the range.
    pub listen: IpAddr,

    /// Port range for port hopping [start, end]
    ///
    /// The server binds to ALL ports in this range simultaneously.
    #[serde(default = "default_port_range")]
    pub port_range: [u16; 2],

    /// Server's tunnel IP address (optional)
    ///
    /// If not specified, defaults to the first usable IP in `tunnel_network`.
    /// For example, if tunnel_network is "10.0.0.0/24", tunnel_ip defaults to "10.0.0.1".
    pub tunnel_ip: Option<Ipv4Addr>,

    /// Tunnel network in CIDR notation
    pub tunnel_network: String,

    /// Enable DNS proxy on the server
    ///
    /// When enabled, the server runs a DNS proxy on its tunnel IP (port 53)
    /// and pushes the tunnel IP to clients as their DNS server.
    /// Clients with dns_proxy enabled will forward queries to this proxy.
    ///
    /// Default: false
    #[serde(default)]
    pub dns_proxy: bool,

    /// Upstream DNS servers for the DNS proxy (only used when dns_proxy = true)
    ///
    /// Supports multiple formats:
    /// - `"IP"` or `"IP:port"` - UDP DNS server (port defaults to 53)
    /// - `"IP/udp"` or `"IP:port/udp"` - Explicit UDP DNS
    /// - `"IP/tcp"` or `"IP:port/tcp"` - TCP DNS
    /// - `"https://..."` - DNS over HTTPS (DoH)
    /// - `"tls://..."` - DNS over TLS (DoT)
    ///
    /// If not specified, defaults to ["8.8.8.8", "1.1.1.1"].
    ///
    /// Example:
    /// ```toml
    /// dns_servers = [
    ///     "8.8.8.8",
    ///     "1.1.1.1:5353/udp",
    ///     "https://cloudflare-dns.com/dns-query",
    ///     "tls://dns.google"
    /// ]
    /// ```
    #[serde(default)]
    pub dns_servers: Vec<String>,

    /// Maximum number of clients
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// Enable NAT/masquerading
    #[serde(default = "default_true")]
    pub enable_nat: bool,

    /// Outbound interface for NAT
    pub nat_interface: Option<String>,
}

impl ServerConfig {
    /// Validate server configuration
    pub fn validate(&self) -> Result<()> {
        if self.port_range[0] > self.port_range[1] {
            return Err(Error::Config(
                "port_range start must be <= end".into(),
            ));
        }

        // Parse tunnel network to validate it
        let net = self
            .tunnel_network
            .parse::<ipnet::Ipv4Net>()
            .map_err(|e| Error::Config(format!("invalid tunnel_network: {}", e)))?;

        // If tunnel_ip is specified, validate it's within the network
        if let Some(ip) = self.tunnel_ip {
            if !net.contains(&ip) {
                return Err(Error::Config(format!(
                    "tunnel_ip {} is not within tunnel_network {}",
                    ip, self.tunnel_network
                )));
            }
        }

        Ok(())
    }

    /// Get the tunnel network as an Ipv4Net
    pub fn tunnel_net(&self) -> Result<ipnet::Ipv4Net> {
        self.tunnel_network
            .parse()
            .map_err(|e| Error::Config(format!("invalid tunnel_network: {}", e)))
    }

    /// Get the server's tunnel IP address
    ///
    /// Returns the configured `tunnel_ip` if set, otherwise derives the first
    /// usable IP from `tunnel_network` (network address + 1).
    ///
    /// For example:
    /// - tunnel_network = "10.0.0.0/24" → returns 10.0.0.1
    /// - tunnel_network = "192.168.1.0/24" → returns 192.168.1.1
    pub fn get_tunnel_ip(&self) -> Result<Ipv4Addr> {
        if let Some(ip) = self.tunnel_ip {
            return Ok(ip);
        }

        // Derive from tunnel_network: use network address + 1
        let net = self.tunnel_net()?;
        let network_addr: u32 = net.network().into();
        let first_ip = Ipv4Addr::from(network_addr + 1);

        // Verify it's within the network
        if !net.contains(&first_ip) {
            return Err(Error::Config(format!(
                "cannot derive tunnel_ip from tunnel_network {}: network too small",
                self.tunnel_network
            )));
        }

        Ok(first_ip)
    }

    /// Parse the configured DNS servers into DnsServerSpec
    ///
    /// Only used when `dns_proxy = true` is configured.
    pub fn parse_dns_servers(&self) -> Result<Vec<DnsServerSpec>> {
        self.dns_servers
            .iter()
            .map(|s| parse_dns_server(s).map_err(Error::from))
            .collect()
    }
}

/// Server address configuration - can be a single host or multiple hosts
///
/// Examples:
/// - Single host: `server = "vpn.example.com"` or `server = "1.2.3.4"`
/// - Multiple hosts: `server = ["vpn1.example.com", "vpn2.example.com"]`
///
/// Note: Port is not specified here - it comes from the `port_range` setting.
/// The client will use all ports in the range for port hopping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerAddress {
    /// Single server host (hostname or IP address, no port)
    Single(String),
    /// Multiple server hosts for multi-homed servers
    Multiple(Vec<String>),
}

impl ServerAddress {
    /// Get all hosts as a slice
    pub fn hosts(&self) -> Vec<&str> {
        match self {
            ServerAddress::Single(s) => vec![s.as_str()],
            ServerAddress::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        match self {
            ServerAddress::Single(s) => s.is_empty(),
            ServerAddress::Multiple(v) => v.is_empty() || v.iter().all(|s| s.is_empty()),
        }
    }
}

/// Client-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server host(s) - can be a single host or list of hosts
    ///
    /// Examples:
    /// - `server = "vpn.example.com"`
    /// - `server = ["vpn1.example.com", "vpn2.example.com", "1.2.3.4"]`
    ///
    /// Ports are determined by `port_range`, not specified here.
    pub server: ServerAddress,

    /// Port range for port hopping [start, end]
    ///
    /// The client will send packets to random ports within this range.
    /// Should match the server's port range.
    #[serde(default = "default_port_range")]
    pub port_range: [u16; 2],

    /// Specific tunnel IP to request
    pub tunnel_ip: Option<Ipv4Addr>,

    /// Route all traffic through the VPN
    #[serde(default = "default_true")]
    pub route_all_traffic: bool,

    /// Routes to exclude from the VPN
    #[serde(default)]
    pub excluded_routes: Vec<String>,

    /// DNS servers to use when connected
    #[serde(default)]
    pub dns: Vec<IpAddr>,

    /// Reconnect automatically
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,

    /// Maximum reconnect attempts (0 = unlimited)
    #[serde(default)]
    pub max_reconnect_attempts: u32,

    /// Reconnect delay in seconds
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay: u64,

    /// Script/command to run when VPN connects
    ///
    /// The script receives the following arguments:
    /// 1. Local tunnel IP address
    /// 2. Netmask (prefix length)
    /// 3. TUN device name
    /// 4. DNS servers (comma-separated, may be empty)
    #[serde(default)]
    pub on_connect: Option<String>,

    /// Script/command to run when VPN disconnects
    ///
    /// The script receives the following arguments:
    /// 1. Local tunnel IP address (may be empty if not connected)
    /// 2. Netmask (prefix length, may be 0 if not connected)
    /// 3. TUN device name (may be empty if not connected)
    /// 4. DNS servers (comma-separated, may be empty)
    #[serde(default)]
    pub on_disconnect: Option<String>,

    /// Enable MSS clamping for TCP traffic through the VPN tunnel
    ///
    /// When enabled, automatically adds iptables rules to clamp TCP MSS
    /// to prevent fragmentation issues with VPN traffic. This is useful
    /// when the VPN client acts as a NAT gateway for other devices.
    ///
    /// **Linux only** - this option is ignored on other platforms.
    ///
    /// Default: false
    #[serde(default)]
    pub mss_fix: bool,

    /// Path loss detection configuration
    ///
    /// When enabled, the client probes each server address to detect
    /// blocked or lossy network paths. Addresses with high packet loss
    /// are temporarily blacklisted.
    ///
    /// Default: disabled
    #[serde(default)]
    pub probe: Option<ProbeConfig>,

    /// Client-side DNS proxy configuration
    ///
    /// When enabled, runs a DNS proxy on the tunnel IP that forwards
    /// queries through the VPN. See `ClientDnsProxyConfig` for options.
    ///
    /// Default: disabled
    #[serde(default)]
    pub dns_proxy: Option<ClientDnsProxyConfig>,
}

/// Configuration for path loss detection probing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// Interval between probes to each address in seconds
    ///
    /// Lower values detect blocked paths faster but generate more traffic.
    /// Default: 10 seconds
    #[serde(default = "default_probe_interval")]
    pub interval: u64,

    /// Loss rate threshold for blacklisting (0.0 - 1.0)
    ///
    /// Addresses with loss rate >= threshold will be blacklisted.
    /// Default: 0.5 (50% loss)
    #[serde(default = "default_probe_threshold")]
    pub threshold: f32,

    /// Duration to keep an address blacklisted in seconds
    ///
    /// After this duration, the address will be probed again.
    /// Default: 300 seconds (5 minutes)
    #[serde(default = "default_probe_blacklist_duration")]
    pub blacklist_duration: u64,

    /// Minimum probes before making blacklist decision
    ///
    /// Prevents false positives from single dropped packets.
    /// Default: 3
    #[serde(default = "default_probe_min_probes")]
    pub min_probes: u32,
}

/// Client-side DNS proxy configuration
///
/// When enabled, the client runs a DNS proxy on the tunnel IP that forwards
/// DNS queries through the VPN tunnel. The proxy uses DNS servers provided
/// by the VPN server during handshake. If the server does not provide DNS
/// servers, the proxy will not start.
///
/// This can be useful for:
/// - Ensuring all DNS queries go through the VPN
/// - Filtering IPv6 DNS records
/// - Populating IP sets with resolved addresses (Linux only)
///
/// # Example
///
/// ```toml
/// [client.dns_proxy]
/// enabled = true
/// port = 53
/// filter_ipv6 = true
/// ipset = "vpn_resolved"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientDnsProxyConfig {
    /// Enable the DNS proxy
    ///
    /// When enabled, a DNS proxy listens on the tunnel IP address.
    /// Default: false
    #[serde(default)]
    pub enabled: bool,

    /// Port to listen on
    ///
    /// The DNS proxy listens on `tunnel_ip:port`.
    /// Default: 53
    #[serde(default = "default_dns_port")]
    pub port: u16,

    /// Filter AAAA (IPv6) records from DNS responses
    ///
    /// When enabled, all AAAA records are removed from DNS responses.
    /// This is useful when you want to force IPv4-only connections.
    /// Default: false
    #[serde(default)]
    pub filter_ipv6: bool,

    /// (Linux only) IP set name to add resolved addresses to
    ///
    /// When configured, resolved IPv4 addresses are added to an IP set.
    /// The implementation tries `nft` (nftables) first, then falls back to
    /// the `ipset` command if nftables is not available.
    ///
    /// For nftables: creates a set in table "ruhop" if it doesn't exist.
    /// For ipset: creates a hash:ip set if it doesn't exist.
    ///
    /// Errors during IP set operations are logged but do not stop the DNS proxy.
    ///
    /// Default: None (disabled)
    #[serde(default)]
    pub ipset: Option<String>,
}

fn default_dns_port() -> u16 {
    53
}

impl ClientConfig {
    /// Validate client configuration
    pub fn validate(&self) -> Result<()> {
        if self.server.is_empty() {
            return Err(Error::Config("server address is required".into()));
        }

        if self.port_range[0] > self.port_range[1] {
            return Err(Error::Config(
                "port_range start must be <= end".into(),
            ));
        }

        // Validate excluded routes
        for route in &self.excluded_routes {
            route
                .parse::<ipnet::IpNet>()
                .map_err(|e| Error::Config(format!("invalid excluded_route '{}': {}", route, e)))?;
        }

        // Validate dns_proxy config if present
        if let Some(ref dns_proxy) = self.dns_proxy {
            if dns_proxy.enabled && dns_proxy.port == 0 {
                return Err(Error::Config("dns_proxy.port cannot be 0".into()));
            }
            // Validate ipset name if configured
            if let Some(ref ipset) = dns_proxy.ipset {
                if ipset.is_empty() {
                    return Err(Error::Config("dns_proxy.ipset cannot be empty".into()));
                }
            }
        }

        Ok(())
    }

    /// Resolve all server IP addresses from the configured hosts
    ///
    /// Returns a list of IP addresses resolved from all configured server hosts.
    /// Each hostname may resolve to multiple IPs. Invalid or unresolvable addresses
    /// are filtered out with an error log, and only valid addresses are returned.
    pub fn resolve_server_ips(&self) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        for host in self.server.hosts() {
            // Try parsing as IP address first
            if let Ok(ip) = host.parse::<IpAddr>() {
                ips.push(ip);
                continue;
            }

            // Try DNS resolution - use port 0 as placeholder since we just want IPs
            let addr_with_port = format!("{}:0", host);
            match addr_with_port.to_socket_addrs() {
                Ok(addrs) => {
                    for addr in addrs {
                        if !ips.contains(&addr.ip()) {
                            ips.push(addr.ip());
                        }
                    }
                }
                Err(e) => {
                    // Log error and skip invalid/unresolvable addresses
                    log::error!("Skipping invalid server address '{}': {}", host, e);
                }
            }
        }

        if ips.is_empty() {
            return Err(Error::Config("no server addresses could be resolved".into()));
        }

        Ok(ips)
    }

    /// Generate all server socket addresses from hosts and port range
    ///
    /// Combines all resolved server IPs with all ports in the configured range.
    /// This is used for port hopping - packets are sent to random addresses from this pool.
    pub fn server_addrs(&self) -> Result<Vec<SocketAddr>> {
        let ips = self.resolve_server_ips()?;
        let mut addrs = Vec::new();

        for ip in ips {
            for port in self.port_range[0]..=self.port_range[1] {
                addrs.push(SocketAddr::new(ip, port));
            }
        }

        Ok(addrs)
    }

    /// Get a random server address for port hopping
    ///
    /// Selects a random address from all available server addresses
    /// (all IPs × all ports in range).
    pub fn random_server_addr(&self, addrs: &[SocketAddr]) -> Option<SocketAddr> {
        addrs.choose(&mut rand::rng()).copied()
    }

    /// Get the first server IP (for route exclusion)
    ///
    /// Returns the first resolved server IP address. Used for adding
    /// routes to bypass the VPN for server traffic.
    pub fn first_server_ip(&self) -> Result<IpAddr> {
        self.resolve_server_ips()?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Config("no server addresses could be resolved".into()))
    }
}

// Default value functions
fn default_mtu() -> u16 {
    1400
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_port_range() -> [u16; 2] {
    [4096, 4196]
}

fn default_max_clients() -> usize {
    100
}

fn default_true() -> bool {
    true
}

fn default_probe_interval() -> u64 {
    10
}

fn default_probe_threshold() -> f32 {
    0.5
}

fn default_probe_blacklist_duration() -> u64 {
    300
}

fn default_probe_min_probes() -> u32 {
    3
}

fn default_reconnect_delay() -> u64 {
    5
}

fn default_log_rotation() -> String {
    "daily".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_server_config() {
        let toml = r#"
[common]
key = "test-key"
mtu = 1400

[server]
listen = "0.0.0.0"
tunnel_ip = "10.0.0.1"
tunnel_network = "10.0.0.0/24"
"#;

        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.common.key, "test-key");
        assert!(config.server.is_some());

        let server = config.server.unwrap();
        assert_eq!(server.tunnel_ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(server.get_tunnel_ip().unwrap(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_server_config_default_tunnel_ip() {
        let toml = r#"
[common]
key = "test-key"

[server]
listen = "0.0.0.0"
tunnel_network = "10.0.0.0/24"
"#;

        let config = Config::from_toml(toml).unwrap();
        let server = config.server.unwrap();

        // tunnel_ip not set, should be None
        assert!(server.tunnel_ip.is_none());

        // get_tunnel_ip() should derive from tunnel_network
        assert_eq!(server.get_tunnel_ip().unwrap(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_server_config_different_network() {
        let toml = r#"
[common]
key = "test-key"

[server]
listen = "0.0.0.0"
tunnel_network = "192.168.100.0/24"
"#;

        let config = Config::from_toml(toml).unwrap();
        let server = config.server.unwrap();

        // Should derive 192.168.100.1 from network
        assert_eq!(server.get_tunnel_ip().unwrap(), Ipv4Addr::new(192, 168, 100, 1));
    }

    #[test]
    fn test_parse_client_config_single_host() {
        let toml = r#"
[common]
key = "test-key"

[client]
server = "127.0.0.1"
route_all_traffic = true
"#;

        let config = Config::from_toml(toml).unwrap();
        assert!(config.client.is_some());

        let client = config.client.unwrap();
        assert!(matches!(client.server, ServerAddress::Single(_)));
        assert!(client.route_all_traffic);

        // Test address generation
        let addrs = client.server_addrs().unwrap();
        // Default port range is 4096-4196, so 101 ports
        assert_eq!(addrs.len(), 101);
    }

    #[test]
    fn test_parse_client_config_multiple_hosts() {
        let toml = r#"
[common]
key = "test-key"

[client]
server = ["127.0.0.1", "127.0.0.2"]
port_range = [5000, 5009]
route_all_traffic = true
"#;

        let config = Config::from_toml(toml).unwrap();
        assert!(config.client.is_some());

        let client = config.client.unwrap();
        assert!(matches!(client.server, ServerAddress::Multiple(_)));
        assert!(client.route_all_traffic);

        // Test address generation: 2 hosts × 10 ports = 20 addresses
        let addrs = client.server_addrs().unwrap();
        assert_eq!(addrs.len(), 20);

        // Verify IPs
        let ips = client.resolve_server_ips().unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_missing_key_fails() {
        let toml = r#"
[server]
listen = "0.0.0.0"
tunnel_ip = "10.0.0.1"
tunnel_network = "10.0.0.0/24"
"#;

        let result = Config::from_toml(toml);
        assert!(result.is_err());
    }
}
