# Ruhop

A Rust implementation of the GoHop VPN protocol - a UDP-based VPN with port hopping capabilities for traffic obfuscation.

[中文文档](README.zh-cn.md)

> **Note**: This is not a full-fledged VPN solution. It lacks multi-user management and enterprise features. If you need a multi-user, enterprise-grade VPN solution, please look elsewhere. The security architecture and implementation of this software have not been independently audited or proven. Use at your own risk.

## Features

- **Port Hopping**: Server listens on all ports in range; client sends to random ports for traffic obfuscation
- **Multi-Address Server**: Client supports connecting to servers with multiple IP addresses
- **AES-256-CBC Encryption**: Secure encryption with Snappy compression
- **IPv4 and IPv6 Support**: Full dual-stack capability (WIP)
- **Cross-Platform**: Works on Linux, macOS, and Windows (including Windows Service support)
- **Auto-Reconnect**: Automatic reconnection on connection loss
- **NAT Support**: Built-in NAT/masquerading for server mode
- **Lifecycle Scripts**: Run custom scripts on connect/disconnect events

## Installation

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/windoze/ruhop/releases) page:

| Platform | Archive | Description |
|----------|---------|-------------|
| Linux x86_64 | `ruhop-linux-amd64.tar.gz` | Standalone binary (musl, static) |
| Linux aarch64 | `ruhop-linux-arm64.tar.gz` | Standalone binary (musl, static) |
| Linux x86_64 | `ruhop-linux-amd64.deb` | Debian/Ubuntu package with systemd service |
| Linux aarch64 | `ruhop-linux-arm64.deb` | Debian/Ubuntu package with systemd service |
| macOS | `ruhop-macos-universal.tar.gz` | Universal binary (Intel + Apple Silicon) |
| Windows | `ruhop-windows-amd64.zip` | Standalone executable |
| Windows | `ruhop-windows-amd64-setup.exe` | NSIS installer (includes wintun.dll) |

**Linux/macOS**: Extract and run directly (executable permissions preserved):
```bash
tar -xzf ruhop-linux-amd64.tar.gz
sudo ./ruhop client -c ruhop.toml
```

**Windows**: Extract the zip or run the installer. The NSIS installer automatically installs `wintun.dll` to System32.

### Build from Source

```bash
# Build all crates
cargo build --release

# The CLI binary will be at target/release/ruhop
```

## Quick Start

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

### Run as Windows Service

```powershell
# Install and start as Windows service (run as Administrator)
ruhop -c C:\path\to\ruhop.toml service install
ruhop service start
```

## Configuration

```toml
[common]
key = "your-secret-key"          # Pre-shared key (required)
mtu = 1400                        # MTU size
log_level = "info"                # Logging level
obfuscation = false               # Enable packet obfuscation
heartbeat_interval = 30           # Heartbeat interval in seconds
# tun_device = "ruhop0"           # TUN device name (ignored on macOS)
# log_file = "/var/log/ruhop"     # Log directory for file logging
# log_rotation = "daily"          # Log rotation: "hourly", "daily", "never"

[server]
listen = "0.0.0.0"                # IP address to listen on
port_range = [4096, 4196]         # Server listens on ALL ports in this range
tunnel_network = "10.0.0.0/24"    # Tunnel network (server uses first IP)
# tunnel_ip = "10.0.0.1"          # Optional: override server tunnel IP
# dns_proxy = true                # Enable DNS proxy on tunnel IP
# dns_servers = ["8.8.8.8"]       # Upstream DNS servers for proxy
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
├── hop-dns/             # DNS proxy implementation
│   └── src/
├── hop-protocol/        # Core protocol library
│   └── src/
├── hop-tun/             # TUN device management
│   └── src/
├── ruhop-engine/        # VPN engine interface
│   └── src/
├── ruhop-cli/           # Command-line interface
│   └── src/
└── docs/
    └── PROTOCOL.md      # Protocol specification
```

## Crates

| Crate | Description |
|-------|-------------|
| [hop-dns](hop-dns/) | DNS proxy implementation for handling DNS requests over the VPN tunnel |
| [hop-protocol](hop-protocol/) | OS-independent protocol library for packet encoding/decoding, encryption, and session management |
| [hop-tun](hop-tun/) | Cross-platform TUN device management, route management, and NAT setup |
| [ruhop-engine](ruhop-engine/) | High-level VPN engine interface for building CLI/GUI applications |
| [ruhop-cli](ruhop-cli/) | Command-line interface for running Ruhop VPN |

## Platform Requirements

### Linux

- Root privileges or the following capabilities:
  - `CAP_NET_ADMIN` - Required for TUN device and route management
  - `CAP_NET_RAW` - Required for TUN device creation
  - `CAP_NET_BIND_SERVICE` - Required for DNS proxy (binding to port 53)
- TUN kernel module loaded (`modprobe tun`)

To run without root:
```bash
sudo setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=eip' /path/to/ruhop
```

NOTE:
- When running without root privileges, make sure you changed the location of log and the control socket to a writable location, otherwise ruhop will not be able to write logs, and the `ruhop status` command will fail to connect to the control socket:
  ```
  [common]
  log_file = "/some/writable/location/ruhop"
  control_socket = "/some/writable/location/ruhop.sock"
  ```
- `iptables`, `ipset`, and/or `nftables`  may not work without root privileges, depending on your system configuration, so expect functionality limitations when running without root.

### macOS

- Root privileges for direct utun access

### Windows

- Administrator privileges
- WinTun driver installed (`wintun.dll` in `C:\Windows\System32`)
  - Download from https://www.wintun.net/
- Optional: Run as Windows Service for persistent connections

## Protocol Overview

The GoHop protocol uses a 4-phase connection lifecycle:

1. **INIT**: Client sends PSH (knock) packets to initiate connection
2. **HANDSHAKE**: Server responds with IP assignment, key exchange
3. **WORKING**: Data transfer via encrypted TUN tunnel
4. **FIN**: Graceful session termination

### Packet Structure

```
┌──────────────────────────────────────────────────────────┐
│                    Encrypted Block                       │
├────────────┬─────────────────────────────────────────────┤
│   16-byte  │              Ciphertext                     │
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

### Using ruhop-engine

```rust
use ruhop_engine::{Config, VpnEngine, VpnRole};

#[tokio::main]
async fn main() -> ruhop_engine::Result<()> {
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
