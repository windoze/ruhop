# Ruhop

A Rust implementation of the GoHop VPN protocol - a UDP-based VPN with port hopping capabilities for traffic obfuscation.

[中文文档](README.zh-cn.md)

> **Note**: This is not a full-fledged VPN solution. It lacks multi-user management and enterprise features. The primary purpose of this program is traffic encryption and obfuscation to evade Deep Packet Inspection (DPI). If you need a multi-user, enterprise-grade VPN solution, please look elsewhere. The security architecture and implementation of this software have not been independently audited or proven. Use at your own risk.

## Features

- **Port Hopping**: Server listens on all ports in range; client sends to random ports for traffic obfuscation
- **Multi-Address Server**: Client supports connecting to servers with multiple IP addresses
- **AES-256-CBC Encryption**: Secure encryption with Snappy compression
- **IPv4 and IPv6 Support**: Full dual-stack capability
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Auto-Reconnect**: Automatic reconnection on connection loss
- **NAT Support**: Built-in NAT/masquerading for server mode
- **Lifecycle Scripts**: Run custom scripts on connect/disconnect events

## Quick Start

### Build

```bash
# Build all crates
cargo build --release

# The CLI binary will be at target/release/ruhop
```

### Generate Configuration

```bash
./target/release/ruhop gen-config -o ruhop.toml
```

### Run Server

```bash
# Edit ruhop.toml with your settings, then:
sudo ./target/release/ruhop server -c ruhop.toml
```

### Run Client

```bash
sudo ./target/release/ruhop client -c ruhop.toml
```

## Configuration

```toml
[common]
key = "your-secret-key"          # Pre-shared key (required)
mtu = 1400                        # MTU size
log_level = "info"                # Logging level
obfuscation = false               # Enable packet obfuscation
heartbeat_interval = 30           # Heartbeat interval in seconds

[server]
listen = "0.0.0.0"                # IP address to listen on
port_range = [4096, 4196]         # Server listens on ALL ports in this range
tunnel_network = "10.0.0.0/24"    # Tunnel network (server uses first IP)
# tunnel_ip = "10.0.0.1"          # Optional: override server tunnel IP
dns = ["8.8.8.8", "8.8.4.4"]      # DNS servers for clients
max_clients = 100                 # Maximum concurrent clients
enable_nat = true                 # Enable NAT/masquerading

[client]
# Single server host:
server = "vpn.example.com"
# Or multiple hosts for multi-homed servers:
# server = ["vpn1.example.com", "vpn2.example.com", "1.2.3.4"]

port_range = [4096, 4196]         # Must match server's port_range
route_all_traffic = true          # Route all traffic through VPN
auto_reconnect = true             # Auto-reconnect on loss
reconnect_delay = 5               # Reconnection delay in seconds
on_connect = "/path/to/script"    # Script to run on connect
on_disconnect = "/path/to/script" # Script to run on disconnect
```

**Port Hopping**: The server binds to all ports in `port_range`. The client sends packets to randomly selected addresses from (hosts × ports). For example, with 2 server hosts and port range [4096, 4196], the client has 202 possible target addresses.

## Project Structure

```
ruhop/
├── hop-protocol/        # Core protocol library
│   └── src/
├── hop-tun/             # TUN device management
│   └── src/
├── ruhop-app-interface/ # VPN engine interface
│   └── src/
├── ruhop-cli/           # Command-line interface
│   └── src/
└── docs/
    └── PROTOCOL.md      # Protocol specification
```

## Crates

| Crate | Description |
|-------|-------------|
| [hop-protocol](hop-protocol/) | OS-independent protocol library for packet encoding/decoding, encryption, and session management |
| [hop-tun](hop-tun/) | Cross-platform TUN device management, route management, and NAT setup |
| [ruhop-app-interface](ruhop-app-interface/) | High-level VPN engine interface for building CLI/GUI applications |
| [ruhop-cli](ruhop-cli/) | Command-line interface for running Ruhop VPN |

## Platform Requirements

### Linux

- Root privileges or `CAP_NET_ADMIN` capability
- TUN kernel module loaded (`modprobe tun`)

### macOS

- Root privileges for direct utun access
- For App Store apps: NetworkExtension entitlements required

### Windows

- Administrator privileges
- WinTun driver installed (https://www.wintun.net/)

## Protocol Overview

The GoHop protocol uses a 4-phase connection lifecycle:

1. **INIT**: Client sends PSH (knock) packets to initiate connection
2. **HANDSHAKE**: Server responds with IP assignment, key exchange
3. **WORKING**: Data transfer via encrypted TUN tunnel
4. **FIN**: Graceful session termination

### Packet Structure

```
┌──────────────────────────────────────────────────────────┐
│                    Encrypted Block                        │
├────────────┬─────────────────────────────────────────────┤
│   16-byte  │              Ciphertext                      │
│     IV     ├─────────────────────┬───────────────────────┤
│            │    16-byte Header   │    Payload + Noise    │
└────────────┴─────────────────────┴───────────────────────┘
```

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the full protocol specification.

## Building for Development

```bash
# Build debug version
cargo build

# Run tests
cargo test

# Run linter
cargo clippy

# Format code
cargo fmt
```

## Using as a Library

### Using ruhop-app-interface

```rust
use ruhop_app_interface::{Config, VpnEngine, VpnRole};

#[tokio::main]
async fn main() -> ruhop_app_interface::Result<()> {
    let config = Config::load("ruhop.toml")?;
    let mut engine = VpnEngine::new(config, VpnRole::Client)?;

    let shutdown_tx = engine.create_shutdown_handle();

    tokio::spawn(async move {
        engine.start().await
    });

    // ... wait for shutdown signal ...
    let _ = shutdown_tx.send(());
    Ok(())
}
```

### Using hop-protocol

```rust
use hop_protocol::{Cipher, Packet, Session};

// Create cipher
let cipher = Cipher::new(b"my-secret-key");

// Encrypt/decrypt data
let encrypted = cipher.encrypt(plaintext)?;
let decrypted = cipher.decrypt(&encrypted)?;

// Create packets
let packet = Packet::data(seq, session_id, &payload);
let bytes = packet.encode();
```

### Using hop-tun

```rust
use hop_tun::{TunDevice, TunConfig};

let config = TunConfig::builder()
    .name("tun0")
    .ipv4("10.0.0.1", 24)
    .mtu(1400)
    .build()?;

let mut device = TunDevice::create(config).await?;

// Read/write packets
let n = device.read(&mut buf).await?;
device.write(&packet).await?;
```

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See [LICENSE](LICENSE) for details.

## Acknowledgments

This project is a Rust implementation of the [GoHop](https://github.com/bigeagle/gohop) protocol originally written in Go.
