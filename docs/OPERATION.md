# Ruhop Operation Guide

This document covers operational considerations, performance tuning, and troubleshooting for deploying Ruhop in production environments.

## Port Range Configuration

### Server Architecture

Ruhop server creates **one UDP socket per port** in the configured port range. Each socket runs its own async receive task. This design enables proper port hopping and NAT traversal but has resource implications.

### Recommended Port Range Sizes

| Environment | Recommended Ports | Example |
|-------------|-------------------|---------|
| Low resource / Testing | 10-50 | `port_range = [4096, 4145]` |
| Standard deployment | 50-100 | `port_range = [4096, 4195]` |
| High security | 100-200 | `port_range = [4096, 4295]` |

**Warning**: Using very large port ranges (500+ ports) can cause:
- Increased memory usage (each socket has buffers)
- Higher CPU overhead from many concurrent async tasks
- Potential packet loss under load due to resource contention
- File descriptor exhaustion (see below)

### File Descriptor Limits

Each port requires a file descriptor. The default limit on many Linux systems is 1024.

**Check current limit:**
```bash
ulimit -n
```

**Increase for current session:**
```bash
ulimit -n 65535
```

**Increase permanently** (add to `/etc/security/limits.conf`):
```
*               soft    nofile          65535
*               hard    nofile          65535
```

For systemd services, add to the unit file:
```ini
[Service]
LimitNOFILE=65535
```

### Performance vs Security Trade-off

More ports provide better traffic obfuscation but consume more resources:

- **10 ports**: Minimal overhead, basic port hopping
- **100 ports**: Good balance of obfuscation and performance
- **1000 ports**: Maximum obfuscation, requires tuned system

## Multi-Homed Server Deployment

### Overview

Ruhop supports servers with multiple IP addresses. The server tracks which local IP received each packet and responds from the same IP for proper NAT traversal.

### Configuration

Server binds to all interfaces:
```toml
[server]
listen = "0.0.0.0"
port_range = [4096, 4196]
```

Client specifies multiple server addresses:
```toml
[client]
server = ["203.0.113.1", "203.0.113.2", "198.51.100.1"]
port_range = [4096, 4196]
```

### How It Works

1. Server uses `IP_PKTINFO` (Linux) or `IP_RECVDSTADDR` (macOS) to track destination IP
2. When responding, server sends from the same local IP that received the request
3. This ensures SNAT/DNAT mappings work correctly through NAT gateways

### Cloud Provider Considerations

#### Azure

Azure VMs with multiple NICs or secondary IPs require proper DNAT/SNAT rules:

- Ensure all external IPs are mapped to internal IPs on the same port range
- The server must bind to `0.0.0.0` to receive on all internal IPs
- Response packets are sent from the correct internal IP, which Azure SNATs to the corresponding external IP

#### AWS

For EC2 instances with multiple Elastic IPs:

- Assign secondary private IPs to the network interface
- Associate Elastic IPs with each private IP
- Security groups must allow UDP on the port range for all Elastic IPs

#### GCP

For Compute Engine with multiple external IPs:

- Use alias IP ranges or multiple network interfaces
- Configure firewall rules to allow UDP on the port range

## Troubleshooting

### Connection Issues

#### Handshake Timeout

**Symptom**: Client shows "handshake timeout"

**Possible causes**:
1. Firewall blocking UDP ports
2. Server not running or crashed
3. Incorrect key configuration
4. NAT gateway issues

**Diagnosis**:
```bash
# Check if server is listening
sudo netstat -ulnp | grep ruhop

# Test UDP connectivity
echo test | nc -u -w1 <server_ip> <port>

# Check server logs for incoming packets
```

#### Packet Loss with Large Port Ranges

**Symptom**: High packet loss (10-40%+) when using large port ranges (500+ ports), even with low traffic

**Cause**: NAT connection tracking table exhaustion on intermediate gateways

When using port hopping with a large address pool (e.g., 3 IPs × 1000 ports = 3000 addresses), each unique source-destination address pair creates a NAT mapping entry on:
- The client's NAT gateway
- Cloud provider's NAT gateway (for DNAT/SNAT)
- Any intermediate NAT devices

With random port selection, traffic quickly creates many NAT entries. When the NAT table fills up:
- Old entries are evicted (even if still in use)
- New packets to evicted mappings are dropped or misrouted
- Response packets may not match any mapping and get dropped

**Solutions**:
1. **Reduce port range** to 50-200 ports - fewer unique address combinations mean fewer NAT entries
2. **Reduce server IP count** if using multi-homed setup - each IP multiplies the address pool size
3. **Increase NAT table size** on gateways you control:
   ```bash
   # Linux - increase conntrack table size
   sysctl -w net.netfilter.nf_conntrack_max=262144
   sysctl -w net.netfilter.nf_conntrack_buckets=65536
   ```
4. **Increase NAT timeout** to keep mappings longer (may not help if table is full):
   ```bash
   sysctl -w net.netfilter.nf_conntrack_udp_timeout=180
   sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180
   ```
5. **Check cloud provider limits** - Azure, AWS, and GCP have NAT gateway connection limits

**Recommended address pool sizes**:
| Scenario | Max Addresses | Example |
|----------|---------------|---------|
| Behind residential NAT | 50-100 | 1 IP × 50-100 ports |
| Cloud with NAT gateway | 100-500 | 1-2 IPs × 50-200 ports |
| Direct public IP (no NAT) | 1000+ | 3 IPs × 500 ports |

#### Decryption Errors

**Symptom**: Server logs show "Decrypt error" or client shows "Unpad Error"

**Possible causes**:
1. Mismatched keys between client and server
2. Packet corruption
3. Receiving packets from a different ruhop instance

**Solution**: Verify the `key` setting matches exactly on both sides.

### Performance Issues

#### High Latency

1. Check network path latency: `ping <server_ip>`
2. Reduce MTU if fragmentation occurs: `mtu = 1300`
3. Ensure server has adequate CPU resources

#### Low Throughput

1. Check for packet loss: `ping -c 100 <tunnel_ip>`
2. Increase socket buffers (see above)
3. Verify no bandwidth limiting on cloud provider

### Logging

Enable debug logging for troubleshooting:

```bash
ruhop -l debug server
ruhop -l debug client
```

Log levels: `error`, `warn`, `info`, `debug`, `trace`

## Security Recommendations

### Key Management

- Use strong, randomly generated keys (32+ characters)
- Rotate keys periodically
- Never transmit keys over insecure channels

Generate a strong key:
```bash
openssl rand -base64 32
```

### Network Security

- Use firewall rules to restrict access to VPN ports
- Consider port knocking or fail2ban for additional protection
- Monitor for unusual traffic patterns

### Running as Non-Root

The server requires root/admin privileges for:
- Creating TUN device
- Modifying routes
- Binding to privileged ports (if using ports < 1024)

For production, consider:
- Using capabilities instead of full root (Linux)
- Running in a container with minimal privileges
- Using ports above 1024

## Systemd Service Example

Create `/etc/systemd/system/ruhop.service`:

```ini
[Unit]
Description=Ruhop VPN Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ruhop -c /etc/ruhop/server.toml server
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/run/ruhop.sock

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable ruhop
sudo systemctl start ruhop
```

## Using Ruhop Client as a NAT Gateway

When running the Ruhop client on a router (e.g., OpenWRT) to provide VPN access for other devices on the network, additional configuration is required.

### Firewall Backend Selection (Linux)

Ruhop uses either nftables or iptables for NAT, MSS clamping, and IP sets. By default, it auto-detects (tries nftables first, falls back to iptables). **Important**: nftables and iptables rules are not interchangeable, so you should explicitly set the backend to match your system:

```toml
[common]
# Explicitly select firewall backend:
# - true: Use nftables (modern, preferred)
# - false: Use iptables/ipset (legacy)
# - Not set: Auto-detect (may break if wrong backend selected)
use_nftables = false  # Use this for systems with iptables
```

On OpenWRT with fw4 (nftables-based), use `use_nftables = true`. On older systems or those using iptables, use `use_nftables = false`.

### Required Setup

1. **Enable IP forwarding** (usually already enabled on routers):
   ```bash
   sysctl -w net.ipv4.ip_forward=1
   ```

2. **Add NAT/masquerade rule** for traffic going through the VPN interface:
   ```bash
   iptables -t nat -A POSTROUTING -o ruhop -j MASQUERADE
   ```

3. **Add MSS clamping** to prevent TCP issues with MTU.

   **Option A**: Enable in config (Linux only, recommended):
   ```toml
   [client]
   mss_fix = true
   ```

   **Option B**: Add manually via iptables:
   ```bash
   iptables -t mangle -A FORWARD -o ruhop -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
   ```

4. **Add routes on client devices** pointing to the router for VPN destinations (if `route_all_traffic = false`).

### OpenWRT Firewall Zone Configuration

**Important**: On OpenWRT, the `ruhop` interface must be added to a firewall zone that allows forwarding from LAN. This is a common issue that's difficult to diagnose.

#### Symptom

- Ping/traffic works FROM the router itself to VPN destinations
- Ping/traffic does NOT work from other LAN devices through the router to VPN destinations
- You see "Destination Port Unreachable" or "Destination Host Unreachable" errors
- The errors come from the router's LAN IP (e.g., 192.168.1.1)

#### Cause

OpenWRT uses nftables (fw4) with a **default DROP policy** on the forward chain. If the `ruhop` interface is not in any firewall zone, forwarded traffic is dropped:

```
chain forward {
    type filter hook forward priority filter; policy drop;
    ...
    iifname { "wg0", "tun0" } jump forward_vpn  # ruhop not listed!
    jump handle_reject  # <-- traffic falls through here
}
```

#### Diagnosis

Check if `ruhop` is in the nftables rules:
```bash
nft list ruleset | grep ruhop
```

If there's no output, the interface is not in any firewall zone.

#### Solution

Add `ruhop` to the VPN firewall zone (or create a new zone):

```bash
# Find the zone index (usually zone[2] for vpn, check your config)
uci show firewall | grep vpn

# Add ruhop device to the zone
uci add_list firewall.@zone[2].device='ruhop'
uci commit firewall
/etc/init.d/firewall reload
```

Or edit `/etc/config/firewall` directly and add `list device 'ruhop'` to the appropriate zone:

```
config zone
    option name 'vpn'
    option input 'DROP'
    option output 'ACCEPT'
    option forward 'ACCEPT'
    option masq '1'
    option mtu_fix '1'
    list device 'ruhop'    # Add this line
```

Then reload the firewall:
```bash
/etc/init.d/firewall reload
```

#### Verification

After adding the interface to the zone:
```bash
# Should now show ruhop in the rules
nft list ruleset | grep ruhop

# Test from a LAN device
ping <vpn_server_tunnel_ip>
```

### Traceroute Not Working Through VPN NAT

If traceroute stops at the VPN server and doesn't show hops beyond:

**Cause**: ICMP Time Exceeded messages from routers beyond the VPN server may not be properly forwarded back through NAT.

**Solution** (Linux/OpenWRT):
```bash
# Allow ICMP error messages to be forwarded
iptables -A FORWARD -p icmp --icmp-type time-exceeded -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT
```

## Monitoring

### Health Check

Check if the VPN is operational:
```bash
ruhop status
```

### Metrics

The server tracks:
- Active sessions count
- Bytes sent/received
- Packet counts

Access via the control socket or status command.

### Alerting Suggestions

Monitor for:
- Server process not running
- High packet loss (> 5%)
- Unusual session counts
- Log errors
