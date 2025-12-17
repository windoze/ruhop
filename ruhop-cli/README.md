# ruhop-cli

Command-line interface for the Ruhop VPN.

## Overview

`ruhop-cli` provides a command-line tool for running Ruhop VPN in server or client mode. It's built on top of `ruhop-engine` and provides a simple way to manage VPN connections from the terminal.

## Installation

### Build from Source

```bash
# Build release binary
cargo build --release -p ruhop-cli

# The binary will be at target/release/ruhop
```

### Install

```bash
# Install to ~/.cargo/bin
cargo install --path ruhop-cli
```

## Usage

```
ruhop [OPTIONS] <COMMAND>

Commands:
  server      Run as VPN server
  client      Run as VPN client
  status      Show status of a running VPN instance
  gen-config  Generate a sample configuration file
  service     Windows service management (Windows only)

Options:
  -c, --config <CONFIG>      Path to configuration file [default: ruhop.toml]
  -l, --log-level <LEVEL>    Log level (error, warn, info, debug, trace) [default: info]
  -h, --help                 Print help
  -V, --version              Print version
```

## Quick Start

### 1. Generate Configuration

```bash
# Generate sample configuration
ruhop gen-config -o ruhop.toml
```

### 2. Edit Configuration

Edit `ruhop.toml` and set your pre-shared key and other options:

```toml
[common]
key = "your-secret-key-here"
mtu = 1400
log_level = "info"

[server]
listen = "0.0.0.0"                # IP address to bind
port_range = [4096, 4196]         # Server listens on ALL ports in this range
tunnel_network = "10.0.0.0/24"    # Tunnel network (server uses first IP)
# tunnel_ip = "10.0.0.1"          # Optional: override server tunnel IP
dns = ["8.8.8.8"]
enable_nat = true

[client]
# Single server host (no port - uses port_range):
server = "your-server.com"
# Or multiple hosts for multi-homed servers:
# server = ["server1.com", "server2.com", "1.2.3.4"]

port_range = [4096, 4196]         # Must match server's port_range
route_all_traffic = true
auto_reconnect = true
```

### 3. Run Server

```bash
# Run as server (requires root)
sudo ruhop server -c ruhop.toml
```

### 4. Run Client

```bash
# Run as client (requires root)
sudo ruhop client -c ruhop.toml
```

## Commands

### server

Run as VPN server.

```bash
ruhop server [OPTIONS]

Options:
  -c, --config <CONFIG>    Path to configuration file [default: ruhop.toml]
  -l, --log-level <LEVEL>  Log level [default: info]
```

The server will:
- Bind to ALL ports in the configured `port_range` simultaneously
- Accept client connections on any of those ports
- Allocate IP addresses from the tunnel network
- Set up NAT if enabled
- Use port hopping when sending responses (random port selection)

### client

Run as VPN client.

```bash
ruhop client [OPTIONS]

Options:
  -c, --config <CONFIG>    Path to configuration file [default: ruhop.toml]
  -l, --log-level <LEVEL>  Log level [default: info]
```

The client will:
- Connect to the configured server
- Perform handshake and receive IP assignment
- Create TUN interface and configure routes
- Route traffic through the VPN tunnel
- Auto-reconnect on connection loss (if enabled)

### gen-config

Generate a sample configuration file.

```bash
ruhop gen-config [OPTIONS]

Options:
  -o, --output <OUTPUT>    Output path [default: ruhop.toml]
```

### status

Show status of a running VPN instance.

```bash
ruhop status [OPTIONS]

Options:
  -s, --socket <SOCKET>    Path to the control socket [default: /var/run/ruhop.sock]
```

### service (Windows only)

Manage Ruhop as a Windows service. The service runs in the background and starts automatically on system boot.

```powershell
ruhop service <ACTION>

Actions:
  install    Install the service
  uninstall  Uninstall the service
  start      Start the service
  stop       Stop the service
  status     Query service status

Options for install:
  -r, --role <ROLE>    Role to run as (client or server) [default: client]
```

#### Install and Start Service

```powershell
# Install as client (default)
ruhop -c C:\path\to\ruhop.toml service install

# Or install as server
ruhop -c C:\path\to\ruhop.toml service install --role server

# Start the service
ruhop service start

# Check status
ruhop service status
```

The service will:
- Copy the configuration to `C:\ProgramData\Ruhop\ruhop.toml`
- Start automatically on system boot
- Run as the LocalSystem account
- Log to `C:\ProgramData\Ruhop\ruhop-service.log`

#### Uninstall Service

```powershell
# Stop first if running
ruhop service stop

# Uninstall
ruhop service uninstall
```

## Configuration

See [ruhop-engine](../ruhop-engine/README.md) for detailed configuration options.

### Minimal Server Config

```toml
[common]
key = "shared-secret"

[server]
listen = "0.0.0.0"
port_range = [4096, 4196]
tunnel_network = "10.0.0.0/24"
```

### Minimal Client Config

```toml
[common]
key = "shared-secret"

[client]
server = "vpn.example.com"
port_range = [4096, 4196]
```

## Logging

Control log verbosity with the `-l` flag:

```bash
# Minimal logging
ruhop -l error client

# Default logging
ruhop -l info client

# Verbose logging
ruhop -l debug client

# Maximum verbosity
ruhop -l trace client
```

You can also use the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug ruhop client
```

## Signal Handling

The CLI handles the following signals for graceful shutdown:

- `SIGINT` (Ctrl+C) - Initiate graceful shutdown
- `SIGTERM` - Initiate graceful shutdown

On Windows, `Ctrl+C` triggers graceful shutdown.

## Lifecycle Scripts

Configure scripts to run on connect/disconnect:

```toml
[client]
on_connect = "/usr/local/bin/vpn-up.sh"
on_disconnect = "/usr/local/bin/vpn-down.sh"
```

Scripts receive arguments: `<local_ip> <peer_ip> <prefix_len> <tun_device>`

Example `vpn-up.sh`:

```bash
#!/bin/bash
LOCAL_IP=$1
PEER_IP=$2
PREFIX=$3
TUN_DEV=$4

echo "VPN connected: $LOCAL_IP/$PREFIX via $TUN_DEV"

# Update DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Custom routes
ip route add 192.168.100.0/24 via $PEER_IP dev $TUN_DEV
```

## Requirements

- **Linux**: Root privileges or `CAP_NET_ADMIN`
- **macOS**: Root privileges
- **Windows**: Administrator privileges, WinTun driver installed (`wintun.dll` in `C:\Windows\System32`)

## Windows-Specific Features

### Administrator Privileges

On Windows, running the VPN requires administrator privileges. If you run `ruhop client` or `ruhop server` without admin rights, the program will prompt you to elevate via UAC.

### Windows Firewall

The VPN automatically configures Windows Firewall rules to allow UDP traffic for the VPN application. These rules are named "Ruhop VPN Inbound" and "Ruhop VPN Outbound".

### Running as a Service

For persistent VPN connections that survive reboots and user logouts, install Ruhop as a Windows service:

```powershell
# Run as Administrator
ruhop -c C:\path\to\ruhop.toml service install
ruhop service start
```

**Important**: When running as a service, `wintun.dll` **must** be placed in `C:\Windows\System32`. The service runs as LocalSystem and will not find the DLL if it's only in the same directory as the executable.

The service configuration is stored in:
- Config file: `C:\ProgramData\Ruhop\ruhop.toml`
- Log file: `C:\ProgramData\Ruhop\ruhop-service.log`
- Registry: `HKLM\SYSTEM\CurrentControlSet\Services\ruhop\Parameters`

## Examples

### Server with Custom Port Range

```bash
# Edit config to use ports 5000-5100
# Then run:
sudo ruhop server -c server.toml -l info
```

### Client with Debug Logging

```bash
sudo ruhop client -c client.toml -l debug
```

### Client with Auto-Reconnect

```toml
[client]
server = "vpn.example.com"
port_range = [4096, 4196]
auto_reconnect = true
max_reconnect_attempts = 0  # Unlimited
reconnect_delay = 5         # 5 seconds between attempts
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0    | Success |
| 1    | Error (configuration, connection, etc.) |

## Troubleshooting

### Permission Denied

```bash
# Linux/macOS: Run with sudo
sudo ruhop client

# Or grant capabilities (Linux)
sudo setcap cap_net_admin=eip ./target/release/ruhop
```

### Connection Timeout

- Check server address and port
- Verify firewall allows UDP traffic on port range
- Check if server is running

### Route Configuration Failed

- Ensure no conflicting routes exist
- Check if tunnel network overlaps with local network

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
