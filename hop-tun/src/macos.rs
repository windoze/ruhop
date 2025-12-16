//! macOS-specific TUN device functionality
//!
//! This module provides macOS-specific extensions and utilities for TUN device management.
//!
//! # Two Approaches for macOS TUN
//!
//! ## 1. Direct utun (Development/Testing)
//!
//! Uses the system's utun interface directly. Requires root privileges.
//! This is what `tun-rs` uses by default.
//!
//! ```bash
//! sudo cargo run --example simple_tun
//! ```
//!
//! ## 2. NetworkExtension Framework (Production Apps)
//!
//! The recommended approach for production macOS/iOS VPN apps. Requires:
//! - An App Extension target (Packet Tunnel Provider)
//! - Proper entitlements (com.apple.developer.networking.networkextension)
//! - App Store distribution or Developer ID signing
//!
//! Enable with the `network-extension` feature:
//! ```toml
//! hop-tun = { version = "0.1", features = ["network-extension"] }
//! ```
//!
//! # NetworkExtension Integration
//!
//! When using NetworkExtension, the typical pattern is:
//!
//! 1. Create a Packet Tunnel Provider App Extension in Swift/Objective-C
//! 2. In `startTunnel()`, configure network settings and get the packet flow fd
//! 3. Pass the file descriptor to Rust code
//! 4. Use `TunDevice::from_fd()` to create the device
//!
//! ## Swift Integration Example
//!
//! ```swift
//! import NetworkExtension
//!
//! class PacketTunnelProvider: NEPacketTunnelProvider {
//!     override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
//!         // Configure tunnel settings
//!         let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")
//!         settings.ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
//!         settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
//!         settings.mtu = 1400
//!
//!         setTunnelNetworkSettings(settings) { [weak self] error in
//!             if let error = error {
//!                 completionHandler(error)
//!                 return
//!             }
//!
//!             // Get the file descriptor from packet flow
//!             guard let fd = self?.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 else {
//!                 completionHandler(NSError(domain: "TunnelError", code: 1))
//!                 return
//!             }
//!
//!             // Pass fd to Rust - call your FFI function
//!             DispatchQueue.global(qos: .userInitiated).async {
//!                 start_rust_tunnel(fd)  // Your Rust FFI function
//!             }
//!
//!             completionHandler(nil)
//!         }
//!     }
//! }
//! ```
//!
//! ## Rust FFI Example
//!
//! ```rust,ignore
//! use hop_tun::TunDevice;
//! use std::os::unix::io::RawFd;
//!
//! #[no_mangle]
//! pub extern "C" fn start_rust_tunnel(fd: RawFd) {
//!     // Create TunDevice from the NetworkExtension file descriptor
//!     let device = unsafe { TunDevice::from_fd(fd, "utun", 1400) }.unwrap();
//!
//!     // Now use the device for packet processing
//!     let mut buf = vec![0u8; 2000];
//!     loop {
//!         match device.read_sync(&mut buf) {
//!             Ok(n) => {
//!                 // Process packet...
//!             }
//!             Err(e) => break,
//!         }
//!     }
//! }
//! ```

use std::process::Command;

use crate::error::{Error, Result};

// ============================================================================
// NetworkExtension Types (when feature is enabled)
// ============================================================================

#[cfg(feature = "network-extension")]
pub mod network_extension {
    //! NetworkExtension framework bindings for macOS/iOS
    //!
    //! This module provides Rust bindings to Apple's NetworkExtension framework
    //! for implementing packet tunnel providers.
    //!
    //! # Requirements
    //!
    //! - macOS 10.11+ or iOS 9.0+
    //! - Packet Tunnel Provider App Extension
    //! - `com.apple.developer.networking.networkextension` entitlement
    //!
    //! # Architecture
    //!
    //! NetworkExtension-based VPNs require a specific app architecture:
    //!
    //! ```text
    //! ┌─────────────────────────────────────────┐
    //! │           Main Application              │
    //! │  - UI for VPN configuration             │
    //! │  - Uses NETunnelProviderManager         │
    //! └─────────────────────────────────────────┘
    //!                     │
    //!                     ▼
    //! ┌─────────────────────────────────────────┐
    //! │     Packet Tunnel Provider Extension    │
    //! │  - Subclass NEPacketTunnelProvider      │
    //! │  - Handles packet encryption/tunneling  │
    //! │  - Runs in separate process             │
    //! └─────────────────────────────────────────┘
    //! ```

    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Configuration for tunnel network settings
    ///
    /// This is used to configure the virtual network interface
    /// that NetworkExtension creates.
    #[derive(Debug, Clone)]
    pub struct TunnelNetworkConfig {
        /// Remote tunnel address (server endpoint)
        pub tunnel_remote_address: String,
        /// IPv4 settings
        pub ipv4: Option<TunnelIPv4Config>,
        /// IPv6 settings
        pub ipv6: Option<TunnelIPv6Config>,
        /// DNS servers
        pub dns_servers: Vec<String>,
        /// DNS search domains
        pub dns_search_domains: Vec<String>,
        /// MTU
        pub mtu: u16,
    }

    impl TunnelNetworkConfig {
        /// Create a new tunnel network configuration
        pub fn new(tunnel_remote_address: impl Into<String>) -> Self {
            Self {
                tunnel_remote_address: tunnel_remote_address.into(),
                ipv4: None,
                ipv6: None,
                dns_servers: Vec::new(),
                dns_search_domains: Vec::new(),
                mtu: 1400,
            }
        }

        /// Set IPv4 configuration
        pub fn with_ipv4(mut self, config: TunnelIPv4Config) -> Self {
            self.ipv4 = Some(config);
            self
        }

        /// Set IPv6 configuration
        pub fn with_ipv6(mut self, config: TunnelIPv6Config) -> Self {
            self.ipv6 = Some(config);
            self
        }

        /// Set DNS servers
        pub fn with_dns(mut self, servers: Vec<String>) -> Self {
            self.dns_servers = servers;
            self
        }

        /// Set DNS search domains
        pub fn with_dns_search_domains(mut self, domains: Vec<String>) -> Self {
            self.dns_search_domains = domains;
            self
        }

        /// Set MTU
        pub fn with_mtu(mut self, mtu: u16) -> Self {
            self.mtu = mtu;
            self
        }
    }

    /// IPv4 tunnel configuration
    #[derive(Debug, Clone)]
    pub struct TunnelIPv4Config {
        /// Local IPv4 addresses
        pub addresses: Vec<Ipv4Addr>,
        /// Subnet masks (one per address)
        pub subnet_masks: Vec<Ipv4Addr>,
        /// Routes to include (route through tunnel)
        pub included_routes: Vec<IPv4Route>,
        /// Routes to exclude (bypass tunnel)
        pub excluded_routes: Vec<IPv4Route>,
    }

    impl TunnelIPv4Config {
        /// Create a new IPv4 configuration
        pub fn new(address: Ipv4Addr, subnet_mask: Ipv4Addr) -> Self {
            Self {
                addresses: vec![address],
                subnet_masks: vec![subnet_mask],
                included_routes: Vec::new(),
                excluded_routes: Vec::new(),
            }
        }

        /// Route all IPv4 traffic through the tunnel
        pub fn route_all(mut self) -> Self {
            self.included_routes.push(IPv4Route::default_route());
            self
        }

        /// Add a specific route
        pub fn with_route(mut self, route: IPv4Route) -> Self {
            self.included_routes.push(route);
            self
        }

        /// Exclude a route from the tunnel
        pub fn exclude_route(mut self, route: IPv4Route) -> Self {
            self.excluded_routes.push(route);
            self
        }
    }

    /// IPv6 tunnel configuration
    #[derive(Debug, Clone)]
    pub struct TunnelIPv6Config {
        /// Local IPv6 addresses
        pub addresses: Vec<Ipv6Addr>,
        /// Network prefix lengths
        pub prefix_lengths: Vec<u8>,
        /// Routes to include
        pub included_routes: Vec<IPv6Route>,
        /// Routes to exclude
        pub excluded_routes: Vec<IPv6Route>,
    }

    impl TunnelIPv6Config {
        /// Create a new IPv6 configuration
        pub fn new(address: Ipv6Addr, prefix_length: u8) -> Self {
            Self {
                addresses: vec![address],
                prefix_lengths: vec![prefix_length],
                included_routes: Vec::new(),
                excluded_routes: Vec::new(),
            }
        }

        /// Route all IPv6 traffic through the tunnel
        pub fn route_all(mut self) -> Self {
            self.included_routes.push(IPv6Route::default_route());
            self
        }
    }

    /// An IPv4 route
    #[derive(Debug, Clone)]
    pub struct IPv4Route {
        /// Destination address
        pub destination: Ipv4Addr,
        /// Subnet mask
        pub subnet_mask: Ipv4Addr,
        /// Gateway (optional)
        pub gateway: Option<Ipv4Addr>,
    }

    impl IPv4Route {
        /// Create a new route
        pub fn new(destination: Ipv4Addr, subnet_mask: Ipv4Addr) -> Self {
            Self {
                destination,
                subnet_mask,
                gateway: None,
            }
        }

        /// Create the default route (0.0.0.0/0) - routes all traffic
        pub fn default_route() -> Self {
            Self {
                destination: Ipv4Addr::UNSPECIFIED,
                subnet_mask: Ipv4Addr::UNSPECIFIED,
                gateway: None,
            }
        }

        /// Set the gateway
        pub fn with_gateway(mut self, gateway: Ipv4Addr) -> Self {
            self.gateway = Some(gateway);
            self
        }
    }

    /// An IPv6 route
    #[derive(Debug, Clone)]
    pub struct IPv6Route {
        /// Destination address
        pub destination: Ipv6Addr,
        /// Network prefix length
        pub prefix_length: u8,
        /// Gateway (optional)
        pub gateway: Option<Ipv6Addr>,
    }

    impl IPv6Route {
        /// Create a new route
        pub fn new(destination: Ipv6Addr, prefix_length: u8) -> Self {
            Self {
                destination,
                prefix_length,
                gateway: None,
            }
        }

        /// Create the default route (::/0) - routes all traffic
        pub fn default_route() -> Self {
            Self {
                destination: Ipv6Addr::UNSPECIFIED,
                prefix_length: 0,
                gateway: None,
            }
        }
    }
}

// Re-export network_extension types when feature is enabled
#[cfg(feature = "network-extension")]
pub use network_extension::*;

// ============================================================================
// Direct utun utilities (always available)
// ============================================================================

/// Get the utun device number from a device name
///
/// For example, "utun3" returns Some(3)
pub fn parse_utun_number(name: &str) -> Option<u32> {
    name.strip_prefix("utun")
        .and_then(|n| n.parse().ok())
}

/// Get the next available utun device number
pub fn get_next_utun_number() -> Result<u32> {
    let output = Command::new("ifconfig")
        .args(["-l"])
        .output()
        .map_err(|e| Error::DeviceCreation(format!("failed to list interfaces: {}", e)))?;

    let interfaces = String::from_utf8_lossy(&output.stdout);
    let mut max_utun: i32 = -1;

    for iface in interfaces.split_whitespace() {
        if let Some(n) = parse_utun_number(iface) {
            max_utun = max_utun.max(n as i32);
        }
    }

    Ok((max_utun + 1) as u32)
}

/// Get interface information using ifconfig
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub mtu: u32,
    pub ipv4: Option<String>,
    pub ipv6: Vec<String>,
    pub is_up: bool,
}

pub fn get_interface_info(name: &str) -> Result<InterfaceInfo> {
    let output = Command::new("ifconfig")
        .arg(name)
        .output()
        .map_err(|e| Error::DeviceNotFound(format!("{}: {}", name, e)))?;

    if !output.status.success() {
        return Err(Error::DeviceNotFound(name.to_string()));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut info = InterfaceInfo {
        name: name.to_string(),
        mtu: 1500,
        ipv4: None,
        ipv6: Vec::new(),
        is_up: false,
    };

    for line in output_str.lines() {
        let line = line.trim();

        if line.contains("mtu") {
            if let Some(mtu_str) = line.split("mtu").nth(1) {
                if let Some(mtu) = mtu_str.split_whitespace().next() {
                    info.mtu = mtu.parse().unwrap_or(1500);
                }
            }
        }

        if line.starts_with("inet ") {
            if let Some(addr) = line.split_whitespace().nth(1) {
                info.ipv4 = Some(addr.to_string());
            }
        }

        if line.starts_with("inet6 ") {
            if let Some(addr) = line.split_whitespace().nth(1) {
                // Remove scope ID if present
                let addr = addr.split('%').next().unwrap_or(addr);
                info.ipv6.push(addr.to_string());
            }
        }

        if line.contains("UP") {
            info.is_up = true;
        }
    }

    Ok(info)
}

/// Check if System Integrity Protection (SIP) allows kernel extensions
///
/// Note: Modern macOS (10.15+) uses system extensions instead of kexts,
/// but utun devices are built-in and don't require extensions.
pub fn check_sip_status() -> Result<bool> {
    let output = Command::new("csrutil")
        .arg("status")
        .output()
        .map_err(|e| Error::NotSupported(format!("failed to check SIP status: {}", e)))?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    Ok(output_str.contains("disabled"))
}

/// Check if running as root
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Get the active network interface (for split tunneling)
pub fn get_primary_interface() -> Result<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| Error::Route(format!("failed to get default route: {}", e)))?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        let line = line.trim();
        if line.starts_with("interface:") {
            if let Some(iface) = line.strip_prefix("interface:") {
                return Ok(iface.trim().to_string());
            }
        }
    }

    Err(Error::Route("primary interface not found".into()))
}

/// Get the primary interface's IP address (for excluding from tunnel)
pub fn get_primary_interface_address() -> Result<String> {
    let iface = get_primary_interface()?;
    let info = get_interface_info(&iface)?;
    info.ipv4.ok_or_else(|| Error::Route("primary interface has no IPv4 address".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_utun_number() {
        assert_eq!(parse_utun_number("utun0"), Some(0));
        assert_eq!(parse_utun_number("utun3"), Some(3));
        assert_eq!(parse_utun_number("utun123"), Some(123));
        assert_eq!(parse_utun_number("tun0"), None);
        assert_eq!(parse_utun_number("en0"), None);
    }

    #[cfg(feature = "network-extension")]
    mod network_extension_tests {
        use super::*;
        use std::net::Ipv4Addr;

        #[test]
        fn test_tunnel_network_config() {
            let config = TunnelNetworkConfig::new("vpn.example.com")
                .with_ipv4(
                    TunnelIPv4Config::new(
                        Ipv4Addr::new(10, 0, 0, 2),
                        Ipv4Addr::new(255, 255, 255, 0),
                    )
                    .route_all(),
                )
                .with_dns(vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()])
                .with_mtu(1400);

            assert_eq!(config.tunnel_remote_address, "vpn.example.com");
            assert_eq!(config.mtu, 1400);
            assert!(config.ipv4.is_some());
        }

        #[test]
        fn test_ipv4_route() {
            let route = IPv4Route::default_route();
            assert_eq!(route.destination, Ipv4Addr::UNSPECIFIED);

            let route = IPv4Route::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0))
                .with_gateway(Ipv4Addr::new(10, 0, 0, 1));
            assert!(route.gateway.is_some());
        }
    }
}
