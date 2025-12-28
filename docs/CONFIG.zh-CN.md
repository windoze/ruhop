# Ruhop 配置参考

本文档描述了 Ruhop VPN 的所有配置选项。配置文件使用 TOML 格式。

## 配置结构

配置文件包含三个主要部分：

| 部分 | 描述 |
|------|------|
| `[common]` | 服务端和客户端共享的设置 |
| `[server]` | 服务端专用设置（仅在服务端模式下使用） |
| `[client]` | 客户端专用设置（仅在客户端模式下使用） |

---

## [common] 部分

服务端和客户端共享的设置。

### key（必填）

用于加密的预共享密钥。服务端和所有客户端必须使用相同的密钥。

```toml
key = "your-secret-key-here"
```

**验证：** 不能为空。

---

### mtu

隧道接口的 MTU（最大传输单元）。

```toml
mtu = 1400
```

**默认值：** `1400`
**验证：** 最小值为 `576`。

---

### log_level

日志详细级别。

```toml
log_level = "info"
```

**默认值：** `"info"`
**可选值：** `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`

---

### log_file

日志文件目录路径。设置后，日志将按时间滚动写入文件。

```toml
log_file = "/var/log/ruhop"
```

**默认值：** 未设置（仅输出到标准输出）
**说明：** 日志文件以日期后缀命名（例如 `ruhop.2024-01-15`）。

---

### log_rotation

日志文件轮转频率。仅在设置了 `log_file` 时生效。

```toml
log_rotation = "daily"
```

**默认值：** `"daily"`
**可选值：** `"hourly"`, `"daily"`, `"never"`

---

### obfuscation

启用数据包混淆以增强流量伪装。

```toml
obfuscation = false
```

**默认值：** `false`

---

### heartbeat_interval

心跳包发送间隔（秒）。

```toml
heartbeat_interval = 30
```

**默认值：** `30`

---

### tun_device

自定义 TUN 设备名称。

```toml
tun_device = "ruhop0"
```

**默认值：** `"ruhop"`（Linux/Windows），自动分配（macOS）
**平台说明：**
- **Linux/Windows：** 使用指定名称或默认为 `"ruhop"`
- **macOS：** 忽略此设置（系统自动分配 `utunX` 名称）

**使用场景：** 在同一台机器上运行多个 Ruhop 实例时设置此项。

---

### control_socket

控制套接字路径（用于 `ruhop status` 命令）。

```toml
control_socket = "/var/run/ruhop.sock"
```

**默认值：** 未设置

---

### use_nftables

在 Linux 上显式选择防火墙后端。

```toml
use_nftables = true
```

**默认值：** 未设置（自动检测）
**可选值：**
- `true` - 使用 nftables（现代，推荐）
- `false` - 使用 iptables/ipset（传统）
- 未设置 - 自动检测（优先尝试 nftables，失败则回退到 iptables）

**平台：** 仅 Linux（在其他平台上忽略）
**警告：** 自动检测可能导致问题，因为 nftables 和 iptables 规则不可互换。

---

## [server] 部分

服务端专用配置。在服务端模式下运行时必须配置。

### listen（必填）

绑定的 IP 地址。服务端会监听 `port_range` 中的所有端口。

```toml
listen = "0.0.0.0"
```

**示例：**
- `"0.0.0.0"` - 监听所有 IPv4 接口
- `"::"` - 监听所有 IPv6 接口
- `"192.168.1.1"` - 监听特定接口

---

### port_range

端口跳跃的端口范围。服务端会同时绑定此范围内的所有端口。

```toml
port_range = [4096, 4196]
```

**默认值：** `[4096, 4196]`（101 个端口）
**验证：** 起始端口必须 ≤ 结束端口。

---

### tunnel_network（必填）

隧道网络的 CIDR 表示法。用于为客户端分配 IP 地址。

```toml
tunnel_network = "10.0.0.0/24"
```

**示例：**
- `"10.0.0.0/24"` - 254 个可用地址
- `"172.16.0.0/16"` - 65,534 个可用地址

---

### tunnel_ip

服务端的隧道 IP 地址。

```toml
tunnel_ip = "10.0.0.1"
```

**默认值：** `tunnel_network` 中的第一个可用 IP（例如 `10.0.0.0/24` 对应 `10.0.0.1`）
**验证：** 必须在 `tunnel_network` 范围内。

---

### dns_proxy

在服务端启用内置 DNS 代理。

```toml
dns_proxy = true
```

**默认值：** `false`
**行为：** 启用后：
- 在 `tunnel_ip:53` 上运行 DNS 代理
- 将 `tunnel_ip` 推送给客户端作为其 DNS 服务器
- 启用了 `dns_proxy` 的客户端会将查询转发到此代理

---

### dns_servers

DNS 代理的上游 DNS 服务器。仅在 `dns_proxy = true` 时使用。

```toml
dns_servers = ["8.8.8.8", "1.1.1.1"]
```

**默认值：** `["8.8.8.8", "1.1.1.1"]`
**支持的格式：**
| 格式 | 描述 |
|------|------|
| `"IP"` | UDP DNS（端口 53） |
| `"IP:port"` | 自定义端口的 UDP DNS |
| `"IP/udp"` 或 `"IP:port/udp"` | 显式 UDP DNS |
| `"IP/tcp"` 或 `"IP:port/tcp"` | TCP DNS |
| `"https://..."` | DNS over HTTPS (DoH) |
| `"tls://..."` | DNS over TLS (DoT) |

**示例：**
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

最大并发客户端连接数。

```toml
max_clients = 100
```

**默认值：** `100`

---

### enable_nat

为客户端流量启用 NAT/伪装。

```toml
enable_nat = true
```

**默认值：** `true`
**说明：** 启用后，客户端流量会通过服务端的出站接口进行伪装。

---

### nat_interface

NAT 的出站接口。

```toml
nat_interface = "eth0"
```

**默认值：** 自动检测
**使用场景：** 当自动检测失败或有多个出站接口时指定。

---

## [client] 部分

客户端专用配置。在客户端模式下运行时必须配置。

### server（必填）

服务器主机名或 IP 地址。端口不在此指定（使用 `port_range`）。

**单个服务器：**
```toml
server = "vpn.example.com"
```

**多个服务器（多宿主）：**
```toml
server = ["vpn1.example.com", "vpn2.example.com", "1.2.3.4"]
```

**验证：** 不能为空。无效或无法解析的地址会被记录并跳过。

---

### port_range

端口跳跃的端口范围。应与服务端的 `port_range` 匹配。

```toml
port_range = [4096, 4196]
```

**默认值：** `[4096, 4196]`
**验证：** 起始端口必须 ≤ 结束端口。

---

### tunnel_ip

向服务器请求特定的隧道 IP。

```toml
tunnel_ip = "10.0.0.5"
```

**默认值：** 未设置（由服务器自动分配 IP）

---

### route_all_traffic

将所有流量路由通过 VPN。

```toml
route_all_traffic = true
```

**默认值：** `true`
**说明：** 设为 `false` 时，仅将发往隧道网络的流量路由通过 VPN。

---

### excluded_routes

从 VPN 路由中排除的网络（旁路路由）。

```toml
excluded_routes = ["192.168.1.0/24", "10.0.0.0/8"]
```

**默认值：** 空
**格式：** CIDR 表示法
**使用场景：** 排除本地网络或特定目标的 VPN 路由。

---

### dns

连接后使用的 DNS 服务器。这些会覆盖系统 DNS。

```toml
dns = ["8.8.8.8", "1.1.1.1"]
```

**默认值：** 空（使用服务器提供的 DNS 或系统 DNS）

---

### auto_reconnect

连接断开时自动重连。

```toml
auto_reconnect = true
```

**默认值：** `true`

---

### max_reconnect_attempts

最大重连尝试次数。设为 `0` 表示无限制。

```toml
max_reconnect_attempts = 0
```

**默认值：** `0`（无限制）

---

### reconnect_delay

重连尝试之间的延迟（秒）。

```toml
reconnect_delay = 5
```

**默认值：** `5`

---

### on_connect

VPN 连接时运行的脚本。

```toml
on_connect = "/path/to/connect-script.sh"
```

**默认值：** 未设置
**传递给脚本的参数：**
1. 本地隧道 IP 地址
2. 子网掩码（前缀长度）
3. TUN 设备名称
4. DNS 服务器（逗号分隔，可能为空）

---

### on_disconnect

VPN 断开时运行的脚本。

```toml
on_disconnect = "/path/to/disconnect-script.sh"
```

**默认值：** 未设置
**传递给脚本的参数：**
1. 本地隧道 IP 地址（可能为空）
2. 子网掩码（前缀长度，可能为 0）
3. TUN 设备名称（可能为空）
4. DNS 服务器（逗号分隔，可能为空）

---

### mss_fix

为 TCP 流量启用 MSS 钳制。

```toml
mss_fix = true
```

**默认值：** `false`
**平台：** 仅 Linux（在其他平台上忽略）
**使用场景：** 当 VPN 客户端作为其他设备的 NAT 网关时，可防止分片问题。

---

## [client.probe] 部分

路径丢包检测配置。启用后，客户端会探测服务器地址以检测被阻断的路径。

```toml
[client.probe]
interval = 10
threshold = 0.5
blacklist_duration = 300
min_probes = 3
```

### interval

对每个地址的探测间隔（秒）。

**默认值：** `10`
**权衡：** 较低的值可更快检测到被阻断的路径，但会产生更多流量。

### threshold

黑名单丢包率阈值（0.0 - 1.0）。

**默认值：** `0.5`（50% 丢包率）
**行为：** 丢包率 ≥ 阈值的地址将被加入黑名单。

### blacklist_duration

地址在重新探测前保持黑名单状态的时间（秒）。

**默认值：** `300`（5 分钟）

### min_probes

做出黑名单决定前的最小探测次数。

**默认值：** `3`
**目的：** 防止单个丢包导致的误判。

---

## [client.dns_proxy] 部分

客户端 DNS 代理配置。运行一个本地 DNS 代理，通过 VPN 转发查询。

```toml
[client.dns_proxy]
enabled = true
port = 53
filter_ipv6 = false
ipset = "vpn_resolved"
```

### enabled

启用 DNS 代理。

**默认值：** `false`
**前提条件：** 服务器必须在握手期间提供 DNS 服务器；否则代理不会启动。

### port

DNS 代理监听的端口。

```toml
port = 53
```

**默认值：** `53`
**地址：** 监听 `tunnel_ip:port`
**验证：** 不能为 `0`。

### filter_ipv6

过滤 DNS 响应中的 AAAA（IPv6）记录。

```toml
filter_ipv6 = false
```

**默认值：** `false`
**使用场景：** 强制使用纯 IPv4 连接。

### ipset

用于添加已解析地址的 IP 集合名称。

```toml
ipset = "vpn_resolved"
```

**默认值：** 未设置（禁用）
**平台：** 仅 Linux
**格式：**
- 简单名称：`"vpn_resolved"` - nftables 使用默认表 "ruhop"
- 表/集合格式：`"custom_table/my_set"` - nftables 使用自定义表名

**行为：**
- 当 `use_nftables = true` 或自动检测时：在指定表中创建 nftables 集合
- 当 `use_nftables = false` 时：使用 ipset（创建 hash:ip 集合，忽略表名）
- 错误会被记录但不会停止 DNS 代理

**示例：**
```toml
ipset = "vpn_resolved"           # nftables: 表 "ruhop", 集合 "vpn_resolved"
ipset = "mangle/bypass"          # nftables: 表 "mangle", 集合 "bypass"
```

**验证：** 如果设置，不能为空字符串。

---

## 完整示例

```toml
# 共享设置
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

# 服务端配置
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

# 客户端配置
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

## 验证规则

加载配置时会进行以下验证：

| 规则 | 部分 | 错误信息 |
|------|------|----------|
| `key` 是必填项 | `[common]` | "key is required" |
| `mtu` ≥ 576 | `[common]` | "MTU X is too small (minimum 576)" |
| `port_range[0]` ≤ `port_range[1]` | `[server]`, `[client]` | "port_range start must be <= end" |
| `tunnel_network` 是有效的 CIDR | `[server]` | "invalid tunnel_network: ..." |
| `tunnel_ip` 在 `tunnel_network` 范围内 | `[server]` | "tunnel_ip X is not within tunnel_network Y" |
| `server` 不为空 | `[client]` | "server address is required" |
| `excluded_routes` 是有效的 CIDR | `[client]` | "invalid excluded_route 'X': ..." |
| `dns_proxy.port` ≠ 0 | `[client.dns_proxy]` | "dns_proxy.port cannot be 0" |
| `dns_proxy.ipset` 非空字符串 | `[client.dns_proxy]` | "dns_proxy.ipset cannot be empty" |
