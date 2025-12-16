# ruhop-app-interface

VPN engine interface for Ruhop - reusable across CLI and GUI applications.

## Overview

`ruhop-app-interface` provides a high-level API for building VPN applications. It abstracts the complexity of the underlying protocol and TUN device handling, making it suitable for both CLI and GUI applications.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  ┌─────────────────┐              ┌─────────────────────┐   │
│  │   ruhop-cli     │              │   Future GUI App    │   │
│  └────────┬────────┘              └──────────┬──────────┘   │
│           │                                   │              │
│           └───────────────┬──────────────────┘              │
│                           ▼                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              ruhop-app-interface                        │ │
│  │  - VpnEngine (main interface)                          │ │
│  │  - Config (TOML configuration)                         │ │
│  │  - Events (status updates, errors)                     │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Library Layer                            │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  hop-protocol   │    │    hop-tun      │                │
│  │  - Encryption   │    │  - TUN device   │                │
│  │  - Packets      │    │  - Routes       │                │
│  │  - Sessions     │    │  - NAT          │                │
│  └─────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ruhop-app-interface = { path = "../ruhop-app-interface" }
```

## Public API

```rust
pub use config::{ClientConfig, Config, ServerConfig};
pub use engine::{VpnEngine, VpnRole};
pub use error::{Error, Result};
pub use event::{VpnEvent, VpnState, VpnStats};
```

## Usage

### Basic Example

```rust
use ruhop_app_interface::{Config, VpnEngine, VpnRole};

#[tokio::main]
async fn main() -> ruhop_app_interface::Result<()> {
    // Load configuration from TOML file
    let config = Config::load("ruhop.toml")?;

    // Create engine (Client or Server mode)
    let mut engine = VpnEngine::new(config, VpnRole::Client)?;

    // Create shutdown handle before spawning (for external control)
    let shutdown_tx = engine.create_shutdown_handle();

    // Spawn engine in background task
    let handle = tokio::spawn(async move {
        engine.start().await
    });

    // ... wait for shutdown signal ...

    // Trigger graceful shutdown
    let _ = shutdown_tx.send(());
    let _ = handle.await;
    Ok(())
}
```

### Custom Event Handler

Implement `EventHandler` to receive VPN lifecycle notifications:

```rust
use std::sync::Arc;
use async_trait::async_trait;
use ruhop_app_interface::{Config, VpnEngine, VpnRole, VpnEvent, VpnState};
use ruhop_app_interface::event::EventHandler;

struct MyHandler;

#[async_trait]
impl EventHandler for MyHandler {
    async fn on_event(&self, event: VpnEvent) {
        match event {
            VpnEvent::StateChanged { old, new } => {
                println!("State: {:?} -> {:?}", old, new);
            }
            VpnEvent::Connected { tunnel_ip, .. } => {
                println!("Connected with IP: {}", tunnel_ip);
            }
            VpnEvent::Disconnected { reason } => {
                println!("Disconnected: {}", reason);
            }
            VpnEvent::Error { message, recoverable } => {
                eprintln!("Error (recoverable={}): {}", recoverable, message);
            }
            VpnEvent::StatsUpdate(stats) => {
                println!("TX: {} bytes, RX: {} bytes", stats.bytes_tx, stats.bytes_rx);
            }
            _ => {}
        }
    }
}

// Attach handler to engine
let engine = VpnEngine::new(config, VpnRole::Client)?
    .with_event_handler(Arc::new(MyHandler));
```

### Querying State and Statistics

```rust
// Get current state
let state = engine.state().await;
if state.is_connected() {
    println!("VPN is connected");
}

// Get traffic statistics
let stats = engine.stats().await;
println!("Uptime: {:?}", stats.uptime);
println!("Total bytes: {}", stats.total_bytes());
```

## Configuration

TOML configuration with three sections:

```toml
[common]
key = "pre-shared-secret"
mtu = 1400
log_level = "info"
obfuscation = false
heartbeat_interval = 30

[server]
listen = "0.0.0.0"                # IP address to bind
port_range = [4096, 4196]         # Server listens on ALL ports in this range
tunnel_network = "10.0.0.0/24"    # Tunnel network (server uses first IP)
# tunnel_ip = "10.0.0.1"          # Optional: override server tunnel IP
dns = ["8.8.8.8", "8.8.4.4"]
max_clients = 100
enable_nat = true
nat_interface = "eth0"

[client]
# Single server host (no port needed - uses port_range):
server = "vpn.example.com"
# Or multiple hosts for multi-homed servers:
# server = ["vpn1.example.com", "vpn2.example.com", "1.2.3.4"]

port_range = [4096, 4196]         # Must match server's port_range
tunnel_ip = "10.0.0.5"            # Optional: request specific IP
route_all_traffic = true
excluded_routes = ["192.168.1.0/24"]
dns = ["8.8.8.8"]
auto_reconnect = true
max_reconnect_attempts = 0        # 0 = unlimited
reconnect_delay = 5
on_connect = "/path/to/connect.sh"
on_disconnect = "/path/to/disconnect.sh"
```

### Port Hopping

The VPN uses port hopping for traffic obfuscation:

- **Server**: Binds to all ports in `port_range` and listens on all simultaneously
- **Client**: Generates all combinations of (server hosts × port range) and sends packets to randomly selected addresses
- Example: 2 server hosts with port range [4096, 4196] = 202 possible target addresses

### Configuration Loading

```rust
use ruhop_app_interface::Config;

// Load from file
let config = Config::load("ruhop.toml")?;

// Parse from string
let config = Config::from_toml(toml_content)?;

// Generate sample configuration
let sample = Config::sample();

// Access role-specific config
let server_cfg = config.server_config()?;
let client_cfg = config.client_config()?;
```

## VPN States

| State | Description |
|-------|-------------|
| `Disconnected` | Not running |
| `Connecting` | Starting up |
| `Handshaking` | Key exchange in progress |
| `Connected` | Operational, tunnel active |
| `Reconnecting` | Auto-reconnecting after loss |
| `Disconnecting` | Graceful shutdown |
| `Error` | Error state |

### State Methods

```rust
let state = engine.state().await;

state.is_active();     // true if connecting, handshaking, connected, or reconnecting
state.is_connected();  // true only if Connected
state.description();   // Human-readable description
```

## VPN Events

| Event | Description |
|-------|-------------|
| `StateChanged { old, new }` | State machine transition |
| `Connected { tunnel_ip, peer_ip }` | Connection established |
| `Disconnected { reason }` | Connection terminated |
| `ClientConnected { session_id, assigned_ip }` | Server: new client |
| `ClientDisconnected { session_id, reason }` | Server: client left |
| `StatsUpdate(VpnStats)` | Traffic statistics |
| `Error { message, recoverable }` | Error notification |
| `Log { level, message }` | Log message |

## VPN Statistics

```rust
pub struct VpnStats {
    pub bytes_rx: u64,           // Bytes received
    pub bytes_tx: u64,           // Bytes transmitted
    pub packets_rx: u64,         // Packet count received
    pub packets_tx: u64,         // Packet count transmitted
    pub uptime: Duration,        // Connection duration
    pub active_sessions: usize,  // Server: active client sessions
    pub last_rx: Option<Instant>,
    pub last_tx: Option<Instant>,
}
```

## Lifecycle Scripts

Client supports `on_connect` and `on_disconnect` scripts that receive:

```
<script> <local_ip> <peer_ip> <prefix_len> <tun_device>
```

Example connect script:

```bash
#!/bin/bash
LOCAL_IP=$1
PEER_IP=$2
PREFIX=$3
TUN_DEV=$4

echo "Connected: $LOCAL_IP via $TUN_DEV"
# Add custom routes, update DNS, etc.
```

## Key Engine Methods

| Method | Description |
|--------|-------------|
| `VpnEngine::new(config, role)` | Create engine instance |
| `.with_event_handler(handler)` | Set custom event handler |
| `.create_shutdown_handle()` | Get broadcast sender for shutdown |
| `.shutdown_handle()` | Get existing shutdown handle |
| `.start().await` | Start the VPN |
| `.stop().await` | Stop the VPN |
| `.state().await` | Get current VPN state |
| `.stats().await` | Get traffic statistics |

## Error Types

```rust
pub enum Error {
    Config(String),           // Configuration error
    ConfigParse(toml::Error), // TOML parsing error
    Io(std::io::Error),       // I/O error
    Protocol(hop_protocol::Error),
    Tun(hop_tun::Error),
    Connection(String),       // Connection error
    Auth(String),             // Authentication error
    Timeout(String),          // Timeout error
    Session(String),          // Session error
    AlreadyRunning,           // Engine already running
    NotRunning,               // Engine not running
    Shutdown,                 // Shutdown in progress
    InvalidState(String),     // Invalid state transition
    AddressAllocation(String),// IP allocation error
    Script(String),           // Script execution error
}

// Helper methods
error.is_recoverable();    // Can retry?
error.is_config_error();   // Configuration issue?
```

## Module Structure

- `config` - TOML configuration parsing (`Config`, `ServerConfig`, `ClientConfig`)
- `engine` - VPN engine implementation (`VpnEngine`, `VpnRole`)
- `event` - Event types and handler trait (`VpnEvent`, `VpnState`, `VpnStats`, `EventHandler`)
- `script` - Lifecycle script execution (`ScriptParams`, `run_script`)
- `error` - Error types (`Error`, `Result`)

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
