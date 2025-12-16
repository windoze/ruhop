//! Configuration types for the VPN engine

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use crate::error::{Error, Result};

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
/// listen = "0.0.0.0:4096"
/// port_range = [4096, 4196]
/// tunnel_ip = "10.0.0.1"
/// tunnel_network = "10.0.0.0/24"
/// dns = ["8.8.8.8", "8.8.4.4"]
///
/// # Client-specific settings
/// [client]
/// server = "vpn.example.com:4096"
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

# Enable packet obfuscation (default: false)
obfuscation = false

# Heartbeat interval in seconds (default: 30)
heartbeat_interval = 30

# Server configuration (used when running as server)
[server]
# Address to listen on
listen = "0.0.0.0:4096"

# Port range for port hopping [start, end]
port_range = [4096, 4196]

# Server's tunnel IP address
tunnel_ip = "10.0.0.1"

# Tunnel network in CIDR notation (for IP allocation)
tunnel_network = "10.0.0.0/24"

# DNS servers to push to clients
dns = ["8.8.8.8", "8.8.4.4"]

# Maximum number of clients (default: 100)
max_clients = 100

# Enable NAT/masquerading for client traffic
enable_nat = true

# Outbound interface for NAT (auto-detected if not set)
# nat_interface = "eth0"

# Client configuration (used when running as client)
[client]
# Server address (required)
server = "vpn.example.com:4096"

# Port range for port hopping (should match server)
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
# Arguments: <local_ip> <peer_ip> <netmask> <tun_device>
# on_connect = "/path/to/connect-script.sh"

# Script to run when VPN disconnects (optional)
# Arguments: <local_ip> <peer_ip> <netmask> <tun_device>
# on_disconnect = "/path/to/disconnect-script.sh"
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
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            key: String::new(),
            mtu: default_mtu(),
            log_level: default_log_level(),
            obfuscation: false,
            heartbeat_interval: default_heartbeat_interval(),
        }
    }
}

/// Server-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on
    pub listen: SocketAddr,

    /// Port range for port hopping [start, end]
    #[serde(default = "default_port_range")]
    pub port_range: [u16; 2],

    /// Server's tunnel IP address
    pub tunnel_ip: Ipv4Addr,

    /// Tunnel network in CIDR notation
    pub tunnel_network: String,

    /// DNS servers to push to clients
    #[serde(default)]
    pub dns: Vec<IpAddr>,

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
        self.tunnel_network
            .parse::<ipnet::Ipv4Net>()
            .map_err(|e| Error::Config(format!("invalid tunnel_network: {}", e)))?;

        Ok(())
    }

    /// Get the tunnel network as an Ipv4Net
    pub fn tunnel_net(&self) -> Result<ipnet::Ipv4Net> {
        self.tunnel_network
            .parse()
            .map_err(|e| Error::Config(format!("invalid tunnel_network: {}", e)))
    }
}

/// Client-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server address
    pub server: String,

    /// Port range for port hopping
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
    /// 2. Peer (server) tunnel IP address
    /// 3. Netmask (prefix length)
    /// 4. TUN device name
    #[serde(default)]
    pub on_connect: Option<String>,

    /// Script/command to run when VPN disconnects
    ///
    /// The script receives the following arguments:
    /// 1. Local tunnel IP address (may be empty if not connected)
    /// 2. Peer (server) tunnel IP address (may be empty if not connected)
    /// 3. Netmask (prefix length, may be 0 if not connected)
    /// 4. TUN device name (may be empty if not connected)
    #[serde(default)]
    pub on_disconnect: Option<String>,
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

        Ok(())
    }

    /// Parse the server address
    pub fn server_addr(&self) -> Result<SocketAddr> {
        // Try parsing as SocketAddr first
        if let Ok(addr) = self.server.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // Try parsing as host:port
        use std::net::ToSocketAddrs;
        self.server
            .to_socket_addrs()
            .map_err(|e| Error::Config(format!("invalid server address '{}': {}", self.server, e)))?
            .next()
            .ok_or_else(|| Error::Config(format!("could not resolve '{}'", self.server)))
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

fn default_reconnect_delay() -> u64 {
    5
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
listen = "0.0.0.0:4096"
tunnel_ip = "10.0.0.1"
tunnel_network = "10.0.0.0/24"
"#;

        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.common.key, "test-key");
        assert!(config.server.is_some());

        let server = config.server.unwrap();
        assert_eq!(server.tunnel_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_parse_client_config() {
        let toml = r#"
[common]
key = "test-key"

[client]
server = "vpn.example.com:4096"
route_all_traffic = true
"#;

        let config = Config::from_toml(toml).unwrap();
        assert!(config.client.is_some());

        let client = config.client.unwrap();
        assert_eq!(client.server, "vpn.example.com:4096");
        assert!(client.route_all_traffic);
    }

    #[test]
    fn test_missing_key_fails() {
        let toml = r#"
[server]
listen = "0.0.0.0:4096"
tunnel_ip = "10.0.0.1"
tunnel_network = "10.0.0.0/24"
"#;

        let result = Config::from_toml(toml);
        assert!(result.is_err());
    }
}
