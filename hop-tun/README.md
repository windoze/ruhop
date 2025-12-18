# hop-tun

Cross-platform TUN device management for VPN implementations.

## Overview

`hop-tun` provides a unified API for creating and managing TUN devices across Linux, macOS, and Windows, along with route management and NAT setup.

## Features

- **TUN Device Management**: Create, configure, and delete TUN interfaces
- **Route Management**: Add/remove routes, configure default gateway
- **NAT/Masquerading**: Set up NAT rules for traffic forwarding
- **Async Support**: Tokio and async-std runtime support
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **NetworkExtension Support**: Integration with macOS/iOS NetworkExtension framework

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hop-tun = { path = "../hop-tun" }
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `async-tokio` | Yes | Async support via Tokio runtime |
| `async-std` | No | Async support via async-std runtime |
| `network-extension` | No | macOS/iOS NetworkExtension framework bindings |

## Platform Requirements

### Linux

- Root privileges or the following capabilities:
  - `CAP_NET_ADMIN` - Required for TUN device and route management
  - `CAP_NET_RAW` - Required for TUN device creation
- TUN kernel module loaded (`modprobe tun`)

To run without root:
```bash
sudo setcap 'cap_net_admin,cap_net_raw=eip' /path/to/binary
```

### macOS

**Development/Testing (Direct utun)**:
- Root privileges
- No additional setup required

**Production Apps (NetworkExtension)**:
- Packet Tunnel Provider App Extension
- `com.apple.developer.networking.networkextension` entitlement
- See `macos` module for integration details

### Windows

- Administrator privileges
- WinTun driver installed (https://www.wintun.net/)

## Public API

```rust
// Core types
pub use TunConfig, TunConfigBuilder;  // Configuration
pub use TunDevice;                     // TUN device
pub use Route, RouteManager;           // Route management
pub use NatManager;                    // NAT management
pub use Error, Result;                 // Error handling

// Platform-specific (Unix + async-tokio)
pub use BorrowedTunDevice;             // For NetworkExtension integration
```

## Usage

### Creating a TUN Device

```rust
use hop_tun::{TunDevice, TunConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = TunConfig::builder()
        .name("tun0")
        .ipv4("10.0.0.1", 24)
        .mtu(1400)
        .build()?;

    // Create the device
    let mut device = TunDevice::create(config).await?;

    // Read packets
    let mut buf = vec![0u8; 2000];
    let n = device.read(&mut buf).await?;
    println!("Received {} bytes", n);

    // Write packets
    device.write(&packet_data).await?;

    Ok(())
}
```

### Configuration Options

```rust
use hop_tun::TunConfig;

let config = TunConfig::builder()
    .name("utun5")                    // Device name (optional on some platforms)
    .ipv4("10.0.0.1", 24)             // IPv4 address with prefix length
    .ipv6("fd00::1", 64)              // IPv6 address (optional)
    .mtu(1400)                        // MTU size
    .build()?;
```

### Route Management

```rust
use hop_tun::{Route, RouteManager};
use std::net::Ipv4Addr;

let mut route_manager = RouteManager::new()?;

// Add a route through the TUN device
let route = Route::new(
    "10.1.0.0".parse()?,
    24,
    Some("10.0.0.1".parse()?),  // Gateway
    Some("tun0".to_string()),    // Interface
);
route_manager.add(&route).await?;

// Remove the route
route_manager.remove(&route).await?;
```

### NAT Management

```rust
use hop_tun::NatManager;

let mut nat = NatManager::new()?;

// Enable NAT for the tunnel network
nat.enable(
    "10.0.0.0/24",           // Source network
    "eth0",                   // Outbound interface
).await?;

// Disable NAT
nat.disable().await?;
```

### macOS NetworkExtension Integration

For production macOS/iOS apps using NetworkExtension:

```rust
#[cfg(all(target_os = "macos", feature = "network-extension"))]
use hop_tun::macos::{PacketTunnelBridge, NEPacketTunnelFlow};

// In your PacketTunnelProvider implementation:
let bridge = PacketTunnelBridge::new(packet_flow);

// Read packets from the tunnel
let packets = bridge.read_packets().await?;

// Write packets to the tunnel
bridge.write_packets(&packets).await?;
```

## Module Structure

- `config` - TUN device configuration (`TunConfig`, `TunConfigBuilder`)
- `device` - TUN device abstraction (`TunDevice`, `BorrowedTunDevice`)
- `route` - Route management (`Route`, `RouteManager`)
- `nat` - NAT/masquerading setup (`NatManager`)
- `error` - Error types (`Error`, `Result`)
- `linux` - Linux-specific implementations
- `macos` - macOS-specific implementations (utun, NetworkExtension)
- `windows` - Windows-specific implementations (WinTun)

## Constants

```rust
pub const DEFAULT_MTU: u16 = 1400;      // Default MTU
pub const MAX_PACKET_SIZE: usize = 65535; // Maximum packet size
```

## Platform-Specific Notes

### Linux

Uses the kernel TUN/TAP driver via `/dev/net/tun`. Route management uses rtnetlink for efficient kernel communication.

### macOS

Two modes of operation:

1. **Direct utun**: For development and CLI tools. Requires root.
2. **NetworkExtension**: For App Store apps. Requires proper entitlements and a Packet Tunnel Provider extension.

### Windows

Uses the WinTun driver (https://www.wintun.net/). The driver must be installed before use.

## Error Handling

```rust
use hop_tun::{Error, Result};

fn example() -> Result<()> {
    let config = TunConfig::builder()
        .ipv4("10.0.0.1", 24)
        .build()
        .map_err(|e| Error::Config(e.to_string()))?;

    // Error variants:
    // - Error::Config - Configuration errors
    // - Error::Io - I/O errors
    // - Error::Permission - Insufficient privileges
    // - Error::NotFound - Device not found
    // - Error::Platform - Platform-specific errors

    Ok(())
}
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
