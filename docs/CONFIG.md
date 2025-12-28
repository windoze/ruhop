# Ruhop Configuration Reference

This document describes all configuration options for Ruhop VPN. Configuration files use TOML format.

## Configuration Structure

The configuration file has three main sections:

| Section | Description |
|---------|-------------|
| `[common]` | Settings shared between server and client modes |
| `[server]` | Server-specific settings (only used when running as server) |
| `[client]` | Client-specific settings (only used when running as client) |

---

## [common] Section

Settings shared by both server and client modes.

### key (required)

Pre-shared key for encryption. Must be the same on server and all clients.

```toml
key = "your-secret-key-here"
```

**Validation:** Cannot be empty.

---

### mtu

MTU (Maximum Transmission Unit) for the tunnel interface.

```toml
mtu = 1400
```

**Default:** `1400`
**Validation:** Minimum value is `576`.

---

### log_level

Logging verbosity level.

```toml
log_level = "info"
```

**Default:** `"info"`
**Options:** `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`

---

### log_file

Directory path for log files. When set, logs are written to files with time-based rolling.

```toml
log_file = "/var/log/ruhop"
```

**Default:** Not set (logs to stdout only)
**Note:** Log files are named with date suffix (e.g., `ruhop.2024-01-15`).

---

### log_rotation

How often to rotate log files. Only used when `log_file` is set.

```toml
log_rotation = "daily"
```

**Default:** `"daily"`
**Options:** `"hourly"`, `"daily"`, `"never"`

---

### obfuscation

Enable packet obfuscation for additional traffic camouflage.

```toml
obfuscation = false
```

**Default:** `false`

---

### heartbeat_interval

Interval between heartbeat packets in seconds.

```toml
heartbeat_interval = 30
```

**Default:** `30`

---

### tun_device

Custom name for the TUN device.

```toml
tun_device = "ruhop0"
```

**Default:** `"ruhop"` (Linux/Windows), auto-assigned (macOS)
**Platform notes:**
- **Linux/Windows:** Uses the specified name or defaults to `"ruhop"`
- **macOS:** Ignored (system auto-assigns `utunX` names)

**Use case:** Set this to run multiple Ruhop instances on the same machine.

---

### control_socket

Path for the control socket (used by `ruhop status` command).

```toml
control_socket = "/var/run/ruhop.sock"
```

**Default:** Not set

---

### use_nftables

Explicitly select the firewall backend on Linux.

```toml
use_nftables = true
```

**Default:** Not set (auto-detect)
**Options:**
- `true` - Use nftables (modern, preferred)
- `false` - Use iptables/ipset (legacy)
- Not set - Auto-detect (tries nftables first, falls back to iptables)

**Platform:** Linux only (ignored on other platforms)
**Warning:** Auto-detection may cause issues as nftables and iptables rules are not interchangeable.

---

## [server] Section

Server-specific configuration. Required when running in server mode.

### listen (required)

IP address to bind on. The server listens on all ports in `port_range`.

```toml
listen = "0.0.0.0"
```

**Examples:**
- `"0.0.0.0"` - Listen on all IPv4 interfaces
- `"::"` - Listen on all IPv6 interfaces
- `"192.168.1.1"` - Listen on specific interface

---

### port_range

Port range for port hopping. The server binds to ALL ports in this range simultaneously.

```toml
port_range = [4096, 4196]
```

**Default:** `[4096, 4196]` (101 ports)
**Validation:** Start port must be ≤ end port.

---

### tunnel_network (required)

CIDR notation for the tunnel network. Used for IP allocation to clients.

```toml
tunnel_network = "10.0.0.0/24"
```

**Examples:**
- `"10.0.0.0/24"` - 254 usable addresses
- `"172.16.0.0/16"` - 65,534 usable addresses

---

### tunnel_ip

Server's tunnel IP address.

```toml
tunnel_ip = "10.0.0.1"
```

**Default:** First usable IP in `tunnel_network` (e.g., `10.0.0.1` for `10.0.0.0/24`)
**Validation:** Must be within `tunnel_network`.

---

### dns_proxy

Enable the built-in DNS proxy on the server.

```toml
dns_proxy = true
```

**Default:** `false`
**Behavior:** When enabled:
- Runs DNS proxy on `tunnel_ip:53`
- Pushes `tunnel_ip` to clients as their DNS server
- Clients with `dns_proxy` enabled forward queries to this proxy

---

### dns_servers

Upstream DNS servers for the DNS proxy. Only used when `dns_proxy = true`.

```toml
dns_servers = ["8.8.8.8", "1.1.1.1"]
```

**Default:** `["8.8.8.8", "1.1.1.1"]`
**Supported formats:**
| Format | Description |
|--------|-------------|
| `"IP"` | UDP DNS (port 53) |
| `"IP:port"` | UDP DNS on custom port |
| `"IP/udp"` or `"IP:port/udp"` | Explicit UDP DNS |
| `"IP/tcp"` or `"IP:port/tcp"` | TCP DNS |
| `"https://..."` | DNS over HTTPS (DoH) |
| `"tls://..."` | DNS over TLS (DoT) |

**Example:**
```toml
dns_servers = [
    "8.8.8.8",
    "1.1.1.1:5353/udp",
    "https://cloudflare-dns.com/dns-query",
    "tls://dns.google"
]
```

---

### max_clients

Maximum number of concurrent client connections.

```toml
max_clients = 100
```

**Default:** `100`

---

### enable_nat

Enable NAT/masquerading for client traffic.

```toml
enable_nat = true
```

**Default:** `true`
**Note:** When enabled, client traffic is masqueraded through the server's outbound interface.

---

### nat_interface

Outbound interface for NAT.

```toml
nat_interface = "eth0"
```

**Default:** Auto-detected
**Use case:** Specify when auto-detection fails or you have multiple outbound interfaces.

---

## [client] Section

Client-specific configuration. Required when running in client mode.

### server (required)

Server hostname(s) or IP address(es). Port is NOT specified here (use `port_range`).

**Single server:**
```toml
server = "vpn.example.com"
```

**Multiple servers (multi-homed):**
```toml
server = ["vpn1.example.com", "vpn2.example.com", "1.2.3.4"]
```

**Validation:** Cannot be empty. Invalid/unresolvable addresses are logged and skipped.

---

### port_range

Port range for port hopping. Should match the server's `port_range`.

```toml
port_range = [4096, 4196]
```

**Default:** `[4096, 4196]`
**Validation:** Start port must be ≤ end port.

---

### tunnel_ip

Request a specific tunnel IP from the server.

```toml
tunnel_ip = "10.0.0.5"
```

**Default:** Not set (server assigns IP automatically)

---

### route_all_traffic

Route all traffic through the VPN.

```toml
route_all_traffic = true
```

**Default:** `true`
**Note:** When `false`, only traffic to the tunnel network is routed through VPN.

---

### excluded_routes

Networks to exclude from VPN routing (bypass routes).

```toml
excluded_routes = ["192.168.1.0/24", "10.0.0.0/8"]
```

**Default:** Empty
**Format:** CIDR notation
**Use case:** Exclude local networks or specific destinations from VPN routing.

---

### dns

DNS servers to use when connected. These override system DNS.

```toml
dns = ["8.8.8.8", "1.1.1.1"]
```

**Default:** Empty (use server-provided DNS or system DNS)

---

### auto_reconnect

Automatically reconnect on connection loss.

```toml
auto_reconnect = true
```

**Default:** `true`

---

### max_reconnect_attempts

Maximum reconnection attempts. Set to `0` for unlimited.

```toml
max_reconnect_attempts = 0
```

**Default:** `0` (unlimited)

---

### reconnect_delay

Delay between reconnection attempts in seconds.

```toml
reconnect_delay = 5
```

**Default:** `5`

---

### on_connect

Script to run when VPN connects.

```toml
on_connect = "/path/to/connect-script.sh"
```

**Default:** Not set
**Arguments passed to script:**
1. Local tunnel IP address
2. Netmask (prefix length)
3. TUN device name
4. DNS servers (comma-separated, may be empty)

---

### on_disconnect

Script to run when VPN disconnects.

```toml
on_disconnect = "/path/to/disconnect-script.sh"
```

**Default:** Not set
**Arguments passed to script:**
1. Local tunnel IP address (may be empty)
2. Netmask (prefix length, may be 0)
3. TUN device name (may be empty)
4. DNS servers (comma-separated, may be empty)

---

### mss_fix

Enable MSS clamping for TCP traffic.

```toml
mss_fix = true
```

**Default:** `false`
**Platform:** Linux only (ignored on other platforms)
**Use case:** When the VPN client acts as a NAT gateway for other devices, this prevents fragmentation issues.

---

## [client.probe] Section

Path loss detection configuration. When enabled, the client probes server addresses to detect blocked paths.

```toml
[client.probe]
interval = 10
threshold = 0.5
blacklist_duration = 300
min_probes = 3
```

### interval

Seconds between probes to each address.

**Default:** `10`
**Trade-off:** Lower values detect blocked paths faster but generate more traffic.

### threshold

Loss rate threshold for blacklisting (0.0 - 1.0).

**Default:** `0.5` (50% loss)
**Behavior:** Addresses with loss rate ≥ threshold are blacklisted.

### blacklist_duration

Seconds to keep an address blacklisted before re-probing.

**Default:** `300` (5 minutes)

### min_probes

Minimum probes before making blacklist decision.

**Default:** `3`
**Purpose:** Prevents false positives from single dropped packets.

---

## [client.dns_proxy] Section

Client-side DNS proxy configuration. Runs a local DNS proxy that forwards queries through the VPN.

```toml
[client.dns_proxy]
enabled = true
port = 53
filter_ipv6 = false
ipset = "vpn_resolved"
```

### enabled

Enable the DNS proxy.

**Default:** `false`
**Prerequisite:** Server must provide DNS servers during handshake; otherwise the proxy won't start.

### port

Port for the DNS proxy to listen on.

```toml
port = 53
```

**Default:** `53`
**Address:** Listens on `tunnel_ip:port`
**Validation:** Cannot be `0`.

### filter_ipv6

Filter AAAA (IPv6) records from DNS responses.

```toml
filter_ipv6 = false
```

**Default:** `false`
**Use case:** Force IPv4-only connections.

### ipset

IP set name to add resolved addresses to.

```toml
ipset = "vpn_resolved"
```

**Default:** Not set (disabled)
**Platform:** Linux only
**Behavior:**
- Tries nftables first (creates set in table "ruhop")
- Falls back to ipset command (creates hash:ip set)
- Errors are logged but don't stop the DNS proxy

**Validation:** Cannot be empty string if set.

---

## Complete Example

```toml
# Shared settings
[common]
key = "my-secure-vpn-key"
mtu = 1400
log_level = "info"
log_file = "/var/log/ruhop"
log_rotation = "daily"
obfuscation = false
heartbeat_interval = 30
tun_device = "ruhop0"
use_nftables = true

# Server configuration
[server]
listen = "0.0.0.0"
port_range = [4096, 4196]
tunnel_network = "10.0.0.0/24"
tunnel_ip = "10.0.0.1"
dns_proxy = true
dns_servers = ["8.8.8.8", "https://cloudflare-dns.com/dns-query"]
max_clients = 100
enable_nat = true
nat_interface = "eth0"

# Client configuration
[client]
server = ["vpn1.example.com", "vpn2.example.com"]
port_range = [4096, 4196]
tunnel_ip = "10.0.0.2"
route_all_traffic = true
excluded_routes = ["192.168.1.0/24"]
dns = ["8.8.8.8"]
auto_reconnect = true
max_reconnect_attempts = 0
reconnect_delay = 5
on_connect = "/etc/ruhop/on-connect.sh"
on_disconnect = "/etc/ruhop/on-disconnect.sh"
mss_fix = true

[client.probe]
interval = 10
threshold = 0.5
blacklist_duration = 300
min_probes = 3

[client.dns_proxy]
enabled = true
port = 53
filter_ipv6 = false
ipset = "vpn_resolved"
```

---

## Validation Rules

The configuration is validated when loaded:

| Rule | Section | Error |
|------|---------|-------|
| `key` is required | `[common]` | "key is required" |
| `mtu` ≥ 576 | `[common]` | "MTU X is too small (minimum 576)" |
| `port_range[0]` ≤ `port_range[1]` | `[server]`, `[client]` | "port_range start must be <= end" |
| `tunnel_network` is valid CIDR | `[server]` | "invalid tunnel_network: ..." |
| `tunnel_ip` within `tunnel_network` | `[server]` | "tunnel_ip X is not within tunnel_network Y" |
| `server` is not empty | `[client]` | "server address is required" |
| `excluded_routes` are valid CIDRs | `[client]` | "invalid excluded_route 'X': ..." |
| `dns_proxy.port` ≠ 0 | `[client.dns_proxy]` | "dns_proxy.port cannot be 0" |
| `dns_proxy.ipset` not empty string | `[client.dns_proxy]` | "dns_proxy.ipset cannot be empty" |
