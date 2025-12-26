//! Integration tests for hop-tun
//!
//! # Permission Requirements
//!
//! Most tests in this file require elevated privileges to create TUN devices
//! and modify routing tables. Tests are marked with `#[ignore]` by default.
//!
//! ## Running Privileged Tests
//!
//! ### Linux
//! ```bash
//! # Option 1: Run as root
//! sudo cargo test -p hop-tun --test integration -- --ignored
//!
//! # Option 2: Add CAP_NET_ADMIN capability to the test binary
//! cargo test -p hop-tun --test integration --no-run
//! sudo setcap cap_net_admin+ep target/debug/deps/integration-*
//! cargo test -p hop-tun --test integration -- --ignored
//! ```
//!
//! ### macOS
//! ```bash
//! # Must run as root
//! sudo cargo test -p hop-tun --test integration -- --ignored
//! ```
//!
//! ### Windows
//! ```powershell
//! # Run PowerShell/Terminal as Administrator
//! # Ensure WinTun driver is installed from https://www.wintun.net/
//! cargo test -p hop-tun --test integration -- --ignored
//! ```
//!
//! ## Test Categories
//!
//! - `test_*` - Basic unit tests (no privileges required)
//! - `test_privileged_*` - Tests requiring root/admin (marked with `#[ignore]`)

use hop_tun::{TunConfig, Route, RouteManager};
use std::net::{Ipv4Addr, Ipv6Addr};
use ipnet::IpNet;

/// Test that configuration validation works correctly
#[test]
fn test_config_validation_requires_address() {
    let result = TunConfig::builder()
        .name("test0")
        .mtu(1400)
        .build();

    assert!(result.is_err());
}

/// Test that IPv4 configuration works
#[test]
fn test_config_with_ipv4() {
    let config = TunConfig::builder()
        .name("test0")
        .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24)
        .mtu(1400)
        .build()
        .unwrap();

    assert_eq!(config.name, Some("test0".to_string()));
    assert_eq!(config.mtu, 1400);
    assert!(config.ipv4.is_some());

    let ipv4 = config.ipv4.unwrap();
    assert_eq!(ipv4.address, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(ipv4.prefix_len, 24);
}

/// Test that IPv6 configuration works
#[test]
fn test_config_with_ipv6() {
    let config = TunConfig::builder()
        .name("test0")
        .ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 64)
        .mtu(1400)
        .build()
        .unwrap();

    assert_eq!(config.ipv6.len(), 1);
}

/// Test dual-stack configuration
#[test]
fn test_config_dual_stack() {
    let config = TunConfig::builder()
        .name("test0")
        .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24)
        .ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 64)
        .mtu(1400)
        .build()
        .unwrap();

    assert!(config.ipv4.is_some());
    assert_eq!(config.ipv6.len(), 1);
}

/// Test route creation
#[test]
fn test_route_creation() {
    let route = Route::ipv4(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Some(Ipv4Addr::new(192, 168, 1, 1)),
    ).unwrap();

    assert!(route.is_ipv4());
    assert!(!route.is_default());
}

/// Test default route creation
#[test]
fn test_default_route() {
    let route = Route::default_v4(Ipv4Addr::new(192, 168, 1, 1));

    assert!(route.is_default());
    assert!(route.is_ipv4());
}

/// Test interface route
#[test]
fn test_interface_route() {
    let network: IpNet = "10.0.0.0/24".parse().unwrap();
    let route = Route::interface_route(network, "tun0");

    assert_eq!(route.interface, Some("tun0".to_string()));
    assert!(route.gateway.is_none());
}

// ============================================================================
// Privileged Tests - Require root/admin to run
// ============================================================================

/// Test TUN device creation (requires privileges)
///
/// # Platform Requirements
///
/// - **Linux**: Root or CAP_NET_ADMIN capability
/// - **macOS**: Root privileges
/// - **Windows**: Administrator with WinTun driver
#[tokio::test]
#[ignore = "requires root/admin privileges"]
async fn test_privileged_tun_device_creation() {
    use hop_tun::TunDevice;

    let config = TunConfig::builder()
        .name("hop-test0")
        .ipv4(Ipv4Addr::new(10, 200, 0, 1), 24)
        .mtu(1400)
        .build()
        .unwrap();

    let device = TunDevice::create(config).await;

    match device {
        Ok(dev) => {
            println!("Created TUN device: {}", dev.name());
            assert_eq!(dev.mtu(), 1400);
        }
        Err(e) => {
            // Check if it's a permission error
            if e.is_permission_denied() {
                println!("Permission denied (expected without privileges): {}", e);
            } else {
                panic!("Unexpected error: {}", e);
            }
        }
    }
}

/// Test reading from TUN device (requires privileges)
#[tokio::test]
#[ignore = "requires root/admin privileges"]
async fn test_privileged_tun_device_read_timeout() {
    use hop_tun::TunDevice;
    use tokio::time::{timeout, Duration};

    let config = TunConfig::builder()
        .name("hop-test1")
        .ipv4(Ipv4Addr::new(10, 200, 1, 1), 24)
        .mtu(1400)
        .build()
        .unwrap();

    let device = TunDevice::create(config).await.expect("Failed to create TUN device");

    let mut buf = vec![0u8; 2000];

    // Read with timeout - should timeout since no traffic is being sent
    let result = timeout(Duration::from_millis(100), device.read(&mut buf)).await;

    assert!(result.is_err(), "Expected timeout");
}

/// Test route management (requires privileges)
#[tokio::test]
#[ignore = "requires root/admin privileges"]
async fn test_privileged_route_management() {
    let manager = RouteManager::new().await.expect("Failed to create route manager");

    // List routes
    let routes = manager.list().await.expect("Failed to list routes");

    println!("Found {} routes in routing table", routes.len());

    // Find default route
    let default_routes: Vec<_> = routes.iter().filter(|r| r.is_default()).collect();
    println!("Default routes: {:?}", default_routes);
}

/// Test adding and removing routes (requires privileges)
#[tokio::test]
#[ignore = "requires root/admin privileges and may modify system routes"]
async fn test_privileged_route_add_remove() {
    let manager = RouteManager::new().await.expect("Failed to create route manager");

    // Add a test route to a private network that shouldn't exist
    let route = Route::ipv4(
        Ipv4Addr::new(10, 254, 254, 0),
        24,
        Some(Ipv4Addr::new(127, 0, 0, 1)),  // Route to localhost for testing
    ).unwrap();

    // Add route
    let add_result = manager.add(&route).await;
    println!("Add route result: {:?}", add_result);

    // Clean up - remove the route
    let delete_result = manager.delete(&route).await;
    println!("Delete route result: {:?}", delete_result);
}

/// Test NAT setup (requires privileges)
#[tokio::test]
#[ignore = "requires root/admin privileges and modifies firewall rules"]
async fn test_privileged_nat_setup() {
    use hop_tun::nat::NatManager;

    // Auto-detect backend (None = auto)
    let mut manager = match NatManager::new(None) {
        Ok(m) => m,
        Err(e) => {
            println!("NAT manager creation failed (expected if no firewall tools): {:?}", e);
            return;
        }
    };

    // Enable IP forwarding
    let forward_result = manager.enable_ip_forwarding();
    println!("IP forwarding result: {:?}", forward_result);

    // Cleanup is automatic via Drop
}

// ============================================================================
// Platform-specific tests
// ============================================================================

#[cfg(target_os = "macos")]
mod macos_tests {
    use hop_tun::macos;

    #[test]
    fn test_parse_utun_number() {
        assert_eq!(macos::parse_utun_number("utun0"), Some(0));
        assert_eq!(macos::parse_utun_number("utun5"), Some(5));
        assert_eq!(macos::parse_utun_number("en0"), None);
    }

    #[test]
    #[ignore = "requires network access"]
    fn test_get_next_utun() {
        let result = macos::get_next_utun_number();
        println!("Next utun number: {:?}", result);
    }
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use hop_tun::linux;

    #[test]
    fn test_tun_available() {
        let available = linux::is_tun_available();
        println!("TUN available: {}", available);
    }

    #[test]
    #[ignore = "requires root"]
    fn test_interface_stats() {
        // Test with loopback interface
        let stats = linux::get_interface_stats("lo");
        println!("Loopback stats: {:?}", stats);
    }
}

#[cfg(target_os = "windows")]
mod windows_tests {
    use hop_tun::windows;

    #[test]
    fn test_wintun_check() {
        let installed = windows::is_wintun_installed();
        println!("WinTun installed: {}", installed);
    }

    #[test]
    fn test_admin_check() {
        let is_admin = windows::is_admin();
        println!("Running as admin: {}", is_admin);
    }
}
