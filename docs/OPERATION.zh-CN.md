# Ruhop 运维指南

本文档涵盖生产环境部署 Ruhop 的运维注意事项、性能调优和故障排查。

## 端口范围配置

### 服务器架构

Ruhop 服务器会为配置的端口范围内的**每个端口创建一个 UDP 套接字**。每个套接字运行独立的异步接收任务。这种设计支持端口跳跃和 NAT 穿透，但会带来资源开销。

### 推荐端口范围大小

| 环境 | 推荐端口数 | 示例 |
|------|-----------|------|
| 低资源/测试环境 | 10-50 | `port_range = [4096, 4145]` |
| 标准部署 | 50-100 | `port_range = [4096, 4195]` |
| 高安全性需求 | 100-200 | `port_range = [4096, 4295]` |

**警告**：使用过大的端口范围（500+ 端口）可能导致：
- 内存使用增加（每个套接字都有缓冲区）
- 大量并发异步任务带来的 CPU 开销增加
- 负载下因资源竞争导致的丢包
- 文件描述符耗尽（见下文）

### 文件描述符限制

每个端口需要一个文件描述符。许多 Linux 系统的默认限制是 1024。

**检查当前限制：**
```bash
ulimit -n
```

**临时增加（当前会话）：**
```bash
ulimit -n 65535
```

**永久增加**（添加到 `/etc/security/limits.conf`）：
```
*               soft    nofile          65535
*               hard    nofile          65535
```

对于 systemd 服务，在单元文件中添加：
```ini
[Service]
LimitNOFILE=65535
```

### 性能与安全的权衡

更多端口提供更好的流量混淆，但消耗更多资源：

- **10 个端口**：最小开销，基本端口跳跃
- **100 个端口**：混淆效果和性能的良好平衡
- **1000 个端口**：最大混淆效果，需要系统调优

## 多宿主服务器部署

### 概述

Ruhop 支持具有多个 IP 地址的服务器。服务器会跟踪哪个本地 IP 接收了每个数据包，并从相同的 IP 响应以实现正确的 NAT 穿透。

### 配置

服务器绑定所有接口：
```toml
[server]
listen = "0.0.0.0"
port_range = [4096, 4196]
```

客户端指定多个服务器地址：
```toml
[client]
server = ["203.0.113.1", "203.0.113.2", "198.51.100.1"]
port_range = [4096, 4196]
```

### 工作原理

1. 服务器使用 `IP_PKTINFO`（Linux）或 `IP_RECVDSTADDR`（macOS）跟踪目标 IP
2. 响应时，服务器从接收请求的相同本地 IP 发送
3. 这确保 SNAT/DNAT 映射在 NAT 网关中正常工作

### 云服务商注意事项

#### Azure

具有多个网卡或辅助 IP 的 Azure 虚拟机需要正确配置 DNAT/SNAT 规则：

- 确保所有外部 IP 在相同端口范围内映射到内部 IP
- 服务器必须绑定到 `0.0.0.0` 以接收所有内部 IP 的流量
- 响应数据包从正确的内部 IP 发送，Azure 会将其 SNAT 到相应的外部 IP

#### AWS

对于具有多个弹性 IP 的 EC2 实例：

- 为网络接口分配辅助私有 IP
- 将弹性 IP 关联到每个私有 IP
- 安全组必须为所有弹性 IP 在端口范围内允许 UDP

#### GCP

对于具有多个外部 IP 的 Compute Engine：

- 使用别名 IP 范围或多个网络接口
- 配置防火墙规则允许端口范围内的 UDP

## 故障排查

### 连接问题

#### 握手超时

**症状**：客户端显示"handshake timeout"

**可能原因**：
1. 防火墙阻止 UDP 端口
2. 服务器未运行或崩溃
3. 密钥配置错误
4. NAT 网关问题

**诊断方法**：
```bash
# 检查服务器是否在监听
sudo netstat -ulnp | grep ruhop

# 测试 UDP 连通性
echo test | nc -u -w1 <服务器IP> <端口>

# 检查服务器日志中的传入数据包
```

#### 大端口范围下的丢包

**症状**：使用大端口范围（500+ 端口）时出现高丢包率（10-40%+），即使流量很低也会发生

**原因**：中间网关上的 NAT 连接跟踪表耗尽

使用大地址池进行端口跳跃时（例如 3 个 IP × 1000 个端口 = 3000 个地址），每个唯一的源-目标地址对都会在以下设备上创建 NAT 映射条目：
- 客户端的 NAT 网关
- 云服务商的 NAT 网关（用于 DNAT/SNAT）
- 任何中间 NAT 设备

由于随机端口选择，流量会快速创建大量 NAT 条目。当 NAT 表满时：
- 旧条目被驱逐（即使仍在使用中）
- 发往被驱逐映射的新数据包被丢弃或错误路由
- 响应数据包可能无法匹配任何映射而被丢弃

**解决方案**：
1. **减少端口范围**至 50-200 个端口 - 更少的唯一地址组合意味着更少的 NAT 条目
2. **减少服务器 IP 数量**（如果使用多宿主设置）- 每个 IP 都会使地址池大小倍增
3. **增加 NAT 表大小**（在您可控制的网关上）：
   ```bash
   # Linux - 增加 conntrack 表大小
   sysctl -w net.netfilter.nf_conntrack_max=262144
   sysctl -w net.netfilter.nf_conntrack_buckets=65536
   ```
4. **增加 NAT 超时时间**以保持映射更长时间（如果表已满可能无效）：
   ```bash
   sysctl -w net.netfilter.nf_conntrack_udp_timeout=180
   sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180
   ```
5. **检查云服务商限制** - Azure、AWS 和 GCP 都有 NAT 网关连接数限制

**推荐地址池大小**：
| 场景 | 最大地址数 | 示例 |
|------|-----------|------|
| 家用 NAT 后 | 50-100 | 1 个 IP × 50-100 个端口 |
| 带 NAT 网关的云环境 | 100-500 | 1-2 个 IP × 50-200 个端口 |
| 直接公网 IP（无 NAT） | 1000+ | 3 个 IP × 500 个端口 |

#### 解密错误

**症状**：服务器日志显示"Decrypt error"或客户端显示"Unpad Error"

**可能原因**：
1. 客户端和服务器的密钥不匹配
2. 数据包损坏
3. 接收到来自其他 ruhop 实例的数据包

**解决方案**：验证两端的 `key` 配置完全一致。

### 性能问题

#### 高延迟

1. 检查网络路径延迟：`ping <服务器IP>`
2. 如果发生分片，减小 MTU：`mtu = 1300`
3. 确保服务器有足够的 CPU 资源

#### 低吞吐量

1. 检查丢包：`ping -c 100 <隧道IP>`
2. 增加套接字缓冲区（见上文）
3. 验证云服务商没有带宽限制

### 日志

启用调试日志进行故障排查：

```bash
ruhop -l debug server
ruhop -l debug client
```

日志级别：`error`、`warn`、`info`、`debug`、`trace`

## 安全建议

### 密钥管理

- 使用强随机生成的密钥（32+ 字符）
- 定期轮换密钥
- 不要通过不安全的渠道传输密钥

生成强密钥：
```bash
openssl rand -base64 32
```

### 网络安全

- 使用防火墙规则限制对 VPN 端口的访问
- 考虑使用端口敲门或 fail2ban 进行额外保护
- 监控异常流量模式

### 以非 root 用户运行

服务器需要 root/管理员权限用于：
- 创建 TUN 设备
- 修改路由
- 绑定特权端口（如果使用 < 1024 的端口）

对于生产环境，考虑：
- 使用 capabilities 替代完整 root 权限（Linux）
- 在具有最小权限的容器中运行
- 使用 1024 以上的端口

## Systemd 服务示例

创建 `/etc/systemd/system/ruhop.service`：

```ini
[Unit]
Description=Ruhop VPN 服务器
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ruhop -c /etc/ruhop/server.toml server
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# 安全加固
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/run/ruhop.sock

[Install]
WantedBy=multi-user.target
```

启用并启动：
```bash
sudo systemctl enable ruhop
sudo systemctl start ruhop
```

## 在 NAT 上使用 Ruhop 客户端

在路由器（如 OpenWRT）上运行 Ruhop 客户端，为网络上的其他设备提供 VPN 访问时，需要额外的配置。

### 防火墙后端选择（Linux）

Ruhop 使用 nftables 或 iptables 进行 NAT、MSS 钳制和 IP 集合管理。默认情况下会自动检测（优先尝试 nftables，回退到 iptables）。**重要**：nftables 和 iptables 规则不可互换，因此应明确设置后端以匹配您的系统：

```toml
[common]
# 明确选择防火墙后端：
# - true: 使用 nftables（现代，推荐）
# - false: 使用 iptables/ipset（传统）
# - 不设置: 自动检测（如果选择错误后端可能会出问题）
use_nftables = false  # 在使用 iptables 的系统上使用此设置
```

在使用 fw4（基于 nftables）的 OpenWRT 上，使用 `use_nftables = true`。在使用 iptables 的旧系统上，使用 `use_nftables = false`。

### 必需的设置

1. **启用 IP 转发**（路由器上通常已启用）：
   ```bash
   sysctl -w net.ipv4.ip_forward=1
   ```

2. **添加 NAT/伪装规则**，用于通过 VPN 接口的流量：
   ```bash
   iptables -t nat -A POSTROUTING -o ruhop -j MASQUERADE
   ```

3. **添加 MSS 钳制**，防止 MTU 导致的 TCP 问题。

   **方式 A**：在配置中启用（仅限 Linux，推荐）：
   ```toml
   [client]
   mss_fix = true
   ```

   **方式 B**：通过 iptables 手动添加：
   ```bash
   iptables -t mangle -A FORWARD -o ruhop -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
   ```

4. **在客户端设备上添加路由**，将 VPN 目标指向路由器（如果 `route_all_traffic = false`）。

### OpenWRT 防火墙区域配置

**重要**：在 OpenWRT 上，必须将 `ruhop` 接口添加到允许从 LAN 转发的防火墙区域。这是一个常见但难以诊断的问题。

#### 症状

- 从路由器本身到 VPN 目标的 ping/流量正常
- 从其他 LAN 设备通过路由器到 VPN 目标的 ping/流量不通
- 看到 "Destination Port Unreachable" 或 "Destination Host Unreachable" 错误
- 错误来自路由器的 LAN IP（如 192.168.1.1）

#### 原因

OpenWRT 使用 nftables（fw4），forward 链的**默认策略是 DROP**。如果 `ruhop` 接口不在任何防火墙区域中，转发流量会被丢弃：

```
chain forward {
    type filter hook forward priority filter; policy drop;
    ...
    iifname { "wg0", "tun0" } jump forward_vpn  # ruhop 未列出！
    jump handle_reject  # <-- 流量落到这里被拒绝
}
```

#### 诊断

检查 `ruhop` 是否在 nftables 规则中：
```bash
nft list ruleset | grep ruhop
```

如果没有输出，说明接口不在任何防火墙区域中。

#### 解决方案

将 `ruhop` 添加到 VPN 防火墙区域（或创建新区域）：

```bash
# 查找区域索引（vpn 通常是 zone[2]，请检查您的配置）
uci show firewall | grep vpn

# 将 ruhop 设备添加到区域
uci add_list firewall.@zone[2].device='ruhop'
uci commit firewall
/etc/init.d/firewall reload
```

或直接编辑 `/etc/config/firewall`，在适当的区域中添加 `list device 'ruhop'`：

```
config zone
    option name 'vpn'
    option input 'DROP'
    option output 'ACCEPT'
    option forward 'ACCEPT'
    option masq '1'
    option mtu_fix '1'
    list device 'ruhop'    # 添加此行
```

然后重新加载防火墙：
```bash
/etc/init.d/firewall reload
```

#### 验证

添加接口到区域后：
```bash
# 现在应该能在规则中看到 ruhop
nft list ruleset | grep ruhop

# 从 LAN 设备测试
ping <VPN服务器隧道IP>
```

### Traceroute 无法穿过 VPN NAT

如果 traceroute 停在 VPN 服务器，无法显示后续跳：

**原因**：VPN 服务器之后路由器返回的 ICMP Time Exceeded 消息可能无法正确通过 NAT 转发回来。

**解决方案**（Linux/OpenWRT）：
```bash
# 允许 ICMP 错误消息被转发
iptables -A FORWARD -p icmp --icmp-type time-exceeded -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT
```

## 基于策略的路由：DNS 代理与 IP 集合

本节介绍如何使用基于 DNS 的 IP 集合实现仅将特定域名的流量通过 VPN 路由。当您需要选择性路由流量时（例如，将 `example.com` 通过 VPN 路由，而其他流量直连），此方案非常有用。

### 概述

配置的工作流程如下：

1. **dnsmasq** 解析 DNS 查询并将解析到的 IP 添加到 IP 集合
2. **IP 集合** 存储指定域名的 IP 地址
3. **策略路由** 将匹配 IP 集合的数据包通过 VPN 路由

### 前提条件

- Ruhop 客户端运行在 Linux/OpenWRT 路由器上
- 已安装并配置 dnsmasq 作为 DNS 服务器
- ipset（用于 iptables）或支持集合的 nftables

### 步骤 1：创建 IP 集合

#### 使用 iptables/ipset：

```bash
# 创建用于存储 VPN 路由地址的 IP 集合
ipset create vpn_domains hash:ip timeout 86400
```

要在重启后保持配置，可添加到 `/etc/rc.local` 或创建 ipset 保存文件。

#### 使用 nftables：

```bash
# 在 nftables 配置中创建集合
nft add table inet ruhop_route
nft add set inet ruhop_route vpn_domains { type ipv4_addr \; flags timeout \; timeout 1d \; }
```

或添加到 `/etc/nftables.conf`：

```
table inet ruhop_route {
    set vpn_domains {
        type ipv4_addr
        flags timeout
        timeout 1d
    }
}
```

### 步骤 2：配置 dnsmasq

将需要通过 VPN 路由的域名添加到 dnsmasq 配置中。

#### 使用 iptables/ipset：

编辑 `/etc/dnsmasq.conf` 或创建 `/etc/dnsmasq.d/vpn-domains.conf`：

```conf
# 通过 VPN 路由这些域名
ipset=/example.com/vpn_domains
ipset=/example.org/vpn_domains
ipset=/.example.net/vpn_domains    # 通配符：所有子域名

# 多个域名可以共享同一个 ipset
ipset=/domain1.com/domain2.com/domain3.com/vpn_domains
```

#### 使用 nftables：

dnsmasq 2.86+ 直接支持 nftables 集合：

```conf
# 对于 nftables 使用 nftset 而不是 ipset
nftset=/example.com/inet#ruhop_route#vpn_domains
nftset=/example.org/inet#ruhop_route#vpn_domains
nftset=/.example.net/inet#ruhop_route#vpn_domains
```

格式为：`nftset=/<域名>/<协议族>#<表名>#<集合名>`

配置完成后重启 dnsmasq：

```bash
# systemd
systemctl restart dnsmasq

# OpenWRT
/etc/init.d/dnsmasq restart
```

### 步骤 3：设置策略路由

#### 创建 VPN 流量的路由表：

```bash
# 添加命名路由表（Linux）
echo "100 vpn" >> /etc/iproute2/rt_tables
```

#### 向 VPN 表添加路由：

```bash
# 将 "vpn" 表中的所有流量通过 ruhop 接口路由
ip route add default dev ruhop table vpn
```

#### 使用 iptables/ipset - 标记匹配 IP 集合的数据包：

```bash
# 标记目标地址在 vpn_domains 集合中的数据包
iptables -t mangle -A PREROUTING -m set --match-set vpn_domains dst -j MARK --set-mark 0x1

# 使用 vpn 表路由被标记的数据包
ip rule add fwmark 0x1 table vpn priority 100
```

#### 使用 nftables：

```bash
nft add chain inet ruhop_route prerouting { type filter hook prerouting priority mangle \; }
nft add rule inet ruhop_route prerouting ip daddr @vpn_domains meta mark set 0x1
```

或添加到 nftables 配置：

```
table inet ruhop_route {
    set vpn_domains {
        type ipv4_addr
        flags timeout
        timeout 1d
    }

    chain prerouting {
        type filter hook prerouting priority mangle;
        ip daddr @vpn_domains meta mark set 0x1
    }
}
```

然后添加路由规则：

```bash
ip rule add fwmark 0x1 table vpn priority 100
```

### 步骤 4：Ruhop 客户端配置

配置 Ruhop 客户端不路由所有流量，因为我们使用选择性路由：

```toml
[client]
server = "vpn.example.com"
route_all_traffic = false    # 重要：不覆盖默认路由
mss_fix = true               # 推荐用于 NAT 网关场景

[common]
key = "your-secret-key"
mtu = 1400
```

### OpenWRT 完整示例

以下是使用 fw4（nftables）的 OpenWRT 完整配置：

#### 1. 安装所需软件包：

```bash
opkg update
opkg install dnsmasq-full    # 支持 ipset/nftset 的完整版本
opkg install ip-full         # 用于策略路由
```

注意：安装 `dnsmasq-full` 前可能需要先卸载 `dnsmasq`。

#### 2. 创建 `/etc/dnsmasq.d/vpn-domains.conf`：

```conf
# 通过 VPN 路由的域名
nftset=/example.com/inet#ruhop_route#vpn_domains
nftset=/streaming-service.com/inet#ruhop_route#vpn_domains
nftset=/.media-cdn.net/inet#ruhop_route#vpn_domains
```

#### 3. 创建 `/etc/nftables.d/ruhop-routing.nft`：

```
table inet ruhop_route {
    set vpn_domains {
        type ipv4_addr
        flags timeout
        timeout 1d
    }

    chain prerouting {
        type filter hook prerouting priority mangle;
        ip daddr @vpn_domains meta mark set 0x1
    }
}
```

#### 4. 创建 `/etc/hotplug.d/iface/99-ruhop-routes`：

```bash
#!/bin/sh

[ "$ACTION" = "ifup" ] && [ "$INTERFACE" = "ruhop" ] && {
    # 如果不存在则创建路由表
    grep -q "^100 vpn$" /etc/iproute2/rt_tables || echo "100 vpn" >> /etc/iproute2/rt_tables

    # 在 vpn 表中添加通过 ruhop 的默认路由
    ip route add default dev ruhop table vpn 2>/dev/null

    # 为标记的数据包添加策略规则
    ip rule del fwmark 0x1 table vpn 2>/dev/null
    ip rule add fwmark 0x1 table vpn priority 100

    logger -t ruhop "已为 ruhop 接口配置策略路由"
}

[ "$ACTION" = "ifdown" ] && [ "$INTERFACE" = "ruhop" ] && {
    ip rule del fwmark 0x1 table vpn 2>/dev/null
    ip route del default dev ruhop table vpn 2>/dev/null
    logger -t ruhop "已移除 ruhop 接口的策略路由"
}
```

设置可执行权限：

```bash
chmod +x /etc/hotplug.d/iface/99-ruhop-routes
```

#### 5. 重新加载服务：

```bash
/etc/init.d/dnsmasq restart
/etc/init.d/firewall reload
```

### 验证

#### 检查 IP 集合内容：

```bash
# 使用 ipset
ipset list vpn_domains

# 使用 nftables
nft list set inet ruhop_route vpn_domains
```

#### 测试 DNS 解析和 IP 集合填充：

```bash
# 查询应通过 VPN 路由的域名
nslookup example.com

# 检查 IP 是否已添加到集合
nft list set inet ruhop_route vpn_domains
```

#### 验证路由：

```bash
# 检查目标地址使用哪个表
ip route get <解析的IP>

# 应显示类似：
# <解析的IP> dev ruhop table vpn ...
```

#### 测试连通性：

```bash
# 从 LAN 设备跟踪到 VPN 路由域名的路由
traceroute example.com
```

### 故障排查

#### IP 未添加到集合

1. 确保 dnsmasq 支持 nftset/ipset：
   ```bash
   dnsmasq --version | grep -E "ipset|nftset"
   ```

2. 检查 dnsmasq 日志：
   ```bash
   logread | grep dnsmasq
   ```

3. 验证客户端使用 dnsmasq 进行 DNS 解析（未绕过它）

#### 流量未通过 VPN 路由

1. 检查数据包是否被标记：
   ```bash
   # 添加计数器查看匹配情况
   nft add rule inet ruhop_route prerouting ip daddr @vpn_domains counter meta mark set 0x1
   nft list chain inet ruhop_route prerouting
   ```

2. 验证路由规则存在：
   ```bash
   ip rule list
   # 应显示：100: from all fwmark 0x1 lookup vpn
   ```

3. 验证 VPN 路由存在：
   ```bash
   ip route show table vpn
   # 应显示：default dev ruhop
   ```

#### DNS 缓存问题

如果在设置 IP 集合之前已访问过域名，其 IP 不会在集合中，直到 DNS 缓存过期。强制重新解析：

```bash
# 清除 dnsmasq 缓存
killall -HUP dnsmasq

# 在客户端设备上也刷新 DNS 缓存
```

## 监控

### 健康检查

检查 VPN 是否正常运行：
```bash
ruhop status
```

### 指标

服务器跟踪：
- 活跃会话数
- 发送/接收字节数
- 数据包计数

通过控制套接字或 status 命令访问。

### 告警建议

监控以下情况：
- 服务器进程未运行
- 高丢包率（> 5%）
- 异常会话数
- 日志错误
