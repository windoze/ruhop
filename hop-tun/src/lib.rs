//! Cross-platform TUN device management for VPN implementations
//!
//! This crate provides a unified API for creating and managing TUN devices
//! across Linux, macOS, and Windows, along with route management and NAT setup.
//!
//! # Features
//!
//! - **TUN Device Management**: Create, configure, and delete TUN interfaces
//! - **Route Management**: Add/remove routes, configure default gateway
//! - **NAT/Masquerading**: Set up NAT rules for traffic forwarding
//! - **Async Support**: Tokio and async-std runtime support
//! - **Cross-Platform**: Works on Linux, macOS, and Windows
//! - **NetworkExtension Support**: Integration with macOS/iOS NetworkExtension framework
//!
//! # Feature Flags
//!
//! - `async-tokio` (default): Async support via Tokio runtime
//! - `async-std`: Async support via async-std runtime
//! - `network-extension`: macOS/iOS NetworkExtension framework bindings
//!
//! # Platform Requirements
//!
//! ## Linux
//! - Root privileges or `CAP_NET_ADMIN` capability
//! - TUN kernel module loaded (`modprobe tun`)
//!
//! ## macOS
//!
//! **Development/Testing (Direct utun)**:
//! - Root privileges
//! - No additional setup required
//!
//! **Production Apps (NetworkExtension)**:
//! - Packet Tunnel Provider App Extension
//! - `com.apple.developer.networking.networkextension` entitlement
//! - See [`macos`] module for integration details
//!
//! ## Windows
//! - Administrator privileges
//! - WinTun driver installed (<https://www.wintun.net/>)
//!
//! # Example
//!
//! ```ignore
//! use hop_tun::{TunDevice, TunConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a TUN device
//!     let config = TunConfig::builder()
//!         .name("tun0")
//!         .ipv4("10.0.0.1", 24)
//!         .mtu(1400)
//!         .build()?;
//!
//!     let mut device = TunDevice::create(config).await?;
//!
//!     // Read packets from the device
//!     let mut buf = vec![0u8; 2000];
//!     let n = device.read(&mut buf).await?;
//!     println!("Received {} bytes", n);
//!
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod device;
pub mod error;
pub mod nat;
pub mod route;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

pub use config::{TunConfig, TunConfigBuilder};
pub use device::TunDevice;
pub use error::{Error, Result};
pub use nat::NatManager;
pub use route::{Route, RouteManager};

// Re-export BorrowedTunDevice for NetworkExtension integration
#[cfg(all(unix, feature = "async-tokio"))]
pub use device::BorrowedTunDevice;

/// Default MTU for TUN devices
pub const DEFAULT_MTU: u16 = 1400;

/// Maximum packet size for TUN devices
pub const MAX_PACKET_SIZE: usize = 65535;
