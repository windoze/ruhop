# ruhop-cli

Ruhop VPN 的命令行界面。

## 概述

`ruhop-cli` 提供了一个命令行工具，用于以服务器或客户端模式运行 Ruhop VPN。它基于 `ruhop-engine` 构建，提供了一种从终端管理 VPN 连接的简单方法。

## 安装

### 从源码构建

```bash
# 构建发布版二进制文件
cargo build --release -p ruhop-cli

# 二进制文件位于 target/release/ruhop
```

### 安装

```bash
# 安装到 ~/.cargo/bin
cargo install --path ruhop-cli
```

### 构建 OpenWRT 软件包

为 OpenWRT 路由器构建 `.ipk` 软件包：

```bash
cd packaging/openwrt

# 为 ARM64 路由器构建（如 RPi 4、现代 ARM 路由器）
./build-openwrt-package.sh aarch64

# 为 x86_64 构建（虚拟路由器、PC 路由器）
./build-openwrt-package.sh x86_64

# 为 MIPS 路由器构建（如 MT7621 设备）
./build-openwrt-package.sh mipsel
```

支持的架构：
- `aarch64` - ARM 64 位
- `armv7` - ARM 32 位（带硬件浮点）
- `x86_64` - Intel/AMD 64 位
- `mipsel` - MIPS 小端序（如 MT7621）
- `mips` - MIPS 大端序

当目标架构与主机架构不同时，脚本会自动使用 `cross` 进行交叉编译。

在路由器上安装：

```bash
scp output/ruhop_*.ipk root@router:/tmp/
ssh root@router 'opkg install /tmp/ruhop_*.ipk'
```

配置并启动：

```bash
# 编辑配置
ssh root@router 'vi /etc/ruhop/ruhop.toml'

# 设置模式（client 或 server）
ssh root@router 'uci set ruhop.main.mode=client && uci commit ruhop'

# 启动服务
ssh root@router '/etc/init.d/ruhop start'
```

## 使用方法

```
ruhop [选项] <命令>

命令:
  server      作为 VPN 服务器运行
  client      作为 VPN 客户端运行
  status      显示运行中 VPN 实例的状态
  gen-config  生成示例配置文件
  service     Windows 服务管理（仅 Windows）

选项:
  -c, --config <CONFIG>      配置文件路径 [默认: ruhop.toml]
  -l, --log-level <LEVEL>    日志级别 (error, warn, info, debug, trace) [默认: info]
  -h, --help                 打印帮助信息
  -V, --version              打印版本信息
```

## 快速开始

### 1. 生成配置

```bash
# 生成示例配置
ruhop gen-config -o ruhop.toml
```

### 2. 编辑配置

编辑 `ruhop.toml` 并设置你的预共享密钥和其他选项：

```toml
[common]
key = "your-secret-key-here"
mtu = 1400
log_level = "info"
# tun_device = "ruhop0"            # 可选：TUN 设备名称（macOS 上忽略）

[server]
listen = "0.0.0.0"                # 监听 IP 地址
port_range = [4096, 4196]         # 服务器监听此范围内的所有端口
tunnel_network = "10.0.0.0/24"    # 隧道网络（服务器使用第一个 IP）
# tunnel_ip = "10.0.0.1"          # 可选：覆盖服务器隧道 IP
# dns_proxy = true                # 在隧道 IP 上启用 DNS 代理
# dns_servers = ["8.8.8.8"]       # 代理的上游 DNS 服务器
enable_nat = true

[client]
# 单个服务器主机（无需端口 - 使用 port_range）：
server = "your-server.com"
# 或多个主机用于多地址服务器：
# server = ["server1.com", "server2.com", "1.2.3.4"]

port_range = [4096, 4196]         # 必须与服务器的 port_range 匹配
route_all_traffic = true
auto_reconnect = true
```

### 3. 运行服务器

```bash
# 作为服务器运行（需要 root 权限）
sudo ruhop server -c ruhop.toml
```

### 4. 运行客户端

```bash
# 作为客户端运行（需要 root 权限）
sudo ruhop client -c ruhop.toml
```

## 命令

### server

作为 VPN 服务器运行。

```bash
ruhop server [选项]

选项:
  -c, --config <CONFIG>    配置文件路径 [默认: ruhop.toml]
  -l, --log-level <LEVEL>  日志级别 [默认: info]
```

服务器将：
- 在配置的地址和端口范围上监听
- 接受客户端连接
- 从隧道网络分配 IP 地址
- 如果启用则设置 NAT
- 处理端口跳跃以混淆流量

### client

作为 VPN 客户端运行。

```bash
ruhop client [选项]

选项:
  -c, --config <CONFIG>    配置文件路径 [默认: ruhop.toml]
  -l, --log-level <LEVEL>  日志级别 [默认: info]
```

客户端将：
- 连接到配置的服务器
- 执行握手并接收 IP 分配
- 创建 TUN 接口并配置路由
- 通过 VPN 隧道路由流量
- 连接断开时自动重连（如果启用）

### gen-config

生成示例配置文件。

```bash
ruhop gen-config [选项]

选项:
  -o, --output <OUTPUT>    输出路径 [默认: ruhop.toml]
```

### status

显示运行中 VPN 实例的状态。

```bash
ruhop status [选项]

选项:
  -s, --socket <SOCKET>    控制套接字路径 [默认: /var/run/ruhop.sock]
```

### service（仅 Windows）

将 Ruhop 作为 Windows 服务管理。服务在后台运行，系统启动时自动启动。

```powershell
ruhop service <操作>

操作:
  install    安装服务
  uninstall  卸载服务
  start      启动服务
  stop       停止服务
  status     查询服务状态

install 选项:
  -r, --role <ROLE>    运行角色（client 或 server）[默认: client]
```

#### 安装并启动服务

```powershell
# 安装为客户端（默认）
ruhop -c C:\path\to\ruhop.toml service install

# 或安装为服务器
ruhop -c C:\path\to\ruhop.toml service install --role server

# 启动服务
ruhop service start

# 检查状态
ruhop service status
```

服务将：
- 复制配置到 `C:\ProgramData\Ruhop\ruhop.toml`
- 系统启动时自动启动
- 以 LocalSystem 账户运行
- 日志记录到 `C:\ProgramData\Ruhop\ruhop-service.log`

#### 卸载服务

```powershell
# 如果正在运行，先停止
ruhop service stop

# 卸载
ruhop service uninstall
```

## 配置

详细配置选项请参阅 [ruhop-engine](../ruhop-engine/README.zh-cn.md)。

### 最小服务器配置

```toml
[common]
key = "shared-secret"

[server]
listen = "0.0.0.0"
port_range = [4096, 4196]
tunnel_network = "10.0.0.0/24"
```

### 最小客户端配置

```toml
[common]
key = "shared-secret"

[client]
server = "vpn.example.com"
port_range = [4096, 4196]
```

## 日志

使用 `-l` 标志控制日志详细程度：

```bash
# 最小日志
ruhop -l error client

# 默认日志
ruhop -l info client

# 详细日志
ruhop -l debug client

# 最大详细程度
ruhop -l trace client
```

你也可以使用 `RUST_LOG` 环境变量：

```bash
RUST_LOG=debug ruhop client
```

## 信号处理

CLI 处理以下信号进行优雅关闭：

- `SIGINT` (Ctrl+C) - 启动优雅关闭
- `SIGTERM` - 启动优雅关闭

在 Windows 上，`Ctrl+C` 触发优雅关闭。

## 生命周期脚本

配置在连接/断开时运行的脚本：

```toml
[client]
on_connect = "/usr/local/bin/vpn-up.sh"
on_disconnect = "/usr/local/bin/vpn-down.sh"
```

脚本接收参数：`<本地IP> <前缀长度> <TUN设备> <DNS服务器>`

- `本地IP`：客户端的隧道 IP 地址
- `前缀长度`：网络前缀长度（例如 24）
- `TUN设备`：TUN 设备名称（例如 utun5、tun0）
- `DNS服务器`：服务器推送的 DNS 服务器 IP，逗号分隔（可能为空）

示例 `vpn-up.sh`：

```bash
#!/bin/bash
LOCAL_IP=$1
PREFIX=$2
TUN_DEV=$3
DNS_SERVERS=$4

echo "VPN 已连接: $LOCAL_IP/$PREFIX 通过 $TUN_DEV"
echo "服务器推送的 DNS: $DNS_SERVERS"

# 使用服务器推送的 DNS 服务器更新 DNS
if [ -n "$DNS_SERVERS" ]; then
    IFS=',' read -ra DNS_ARRAY <<< "$DNS_SERVERS"
    for dns in "${DNS_ARRAY[@]}"; do
        echo "nameserver $dns"
    done | sudo tee /etc/resolv.conf
fi

# 通过 TUN 设备添加自定义路由
ip route add 192.168.100.0/24 dev $TUN_DEV
```

## 要求

- **Linux**：Root 权限或以下能力：
  - `CAP_NET_ADMIN` - TUN 设备和路由管理所需
  - `CAP_NET_RAW` - TUN 设备创建所需
  - `CAP_NET_BIND_SERVICE` - DNS 代理所需（绑定 53 端口）
- **macOS**：Root 权限
- **Windows**：管理员权限，已安装 WinTun 驱动（`wintun.dll` 位于 `C:\Windows\System32`）

## Windows 特定功能

### 管理员权限

在 Windows 上，运行 VPN 需要管理员权限。如果在没有管理员权限的情况下运行 `ruhop client` 或 `ruhop server`，程序会提示通过 UAC 提升权限。

### Windows 防火墙

VPN 会自动配置 Windows 防火墙规则以允许 VPN 应用程序的 UDP 流量。这些规则名为 "Ruhop VPN Inbound" 和 "Ruhop VPN Outbound"。

### 作为服务运行

如果需要在重启和用户注销后保持 VPN 连接，可以将 Ruhop 安装为 Windows 服务：

```powershell
# 以管理员身份运行
ruhop -c C:\path\to\ruhop.toml service install
ruhop service start
```

**重要**：作为服务运行时，`wintun.dll` **必须**放置在 `C:\Windows\System32` 目录下。服务以 LocalSystem 账户运行，如果 DLL 仅在可执行文件同目录下则无法找到。

服务配置存储在：
- 配置文件：`C:\ProgramData\Ruhop\ruhop.toml`
- 日志文件：`C:\ProgramData\Ruhop\ruhop-service.log`
- 注册表：`HKLM\SYSTEM\CurrentControlSet\Services\ruhop\Parameters`

## 示例

### 使用自定义端口范围的服务器

```bash
# 编辑配置使用端口 5000-5100
# 然后运行：
sudo ruhop server -c server.toml -l info
```

### 带调试日志的客户端

```bash
sudo ruhop client -c client.toml -l debug
```

### 带自动重连的客户端

```toml
[client]
server = "vpn.example.com"
port_range = [4096, 4196]
auto_reconnect = true
max_reconnect_attempts = 0  # 无限制
reconnect_delay = 5         # 尝试间隔 5 秒
```

## 退出码

| 代码 | 描述 |
|------|-------------|
| 0    | 成功 |
| 1    | 错误（配置、连接等） |

## 故障排除

### 权限被拒绝

```bash
# Linux/macOS：使用 sudo 运行
sudo ruhop client

# 或授予 capabilities（Linux）
sudo setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=eip' ./target/release/ruhop
```

### 连接超时

- 检查服务器地址和端口
- 验证防火墙允许端口范围内的 UDP 流量
- 检查服务器是否正在运行

### 路由配置失败

- 确保没有冲突的路由存在
- 检查隧道网络是否与本地网络重叠

## 许可证

AGPL-3.0-or-later。详情请参阅 [LICENSE](../LICENSE)。
