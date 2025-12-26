# Ruhop

GoHop VPN 协议的 Rust 实现 - 一个支持端口跳跃的 UDP VPN，用于流量混淆。

[English](README.md)

> **注意**：本程序不是一个完整的 VPN 解决方案，不支持多用户功能和企业级管理功能。如果您需要多用户、企业级的 VPN 解决方案，请寻找其他产品。本软件的安全架构和实现未经独立审计或验证，使用风险自负。

## 特性

- **端口跳跃**：服务器监听范围内所有端口；客户端发送到随机端口，用于流量混淆
- **多地址服务器**：客户端支持连接到具有多个 IP 地址的服务器
- **AES-256-CBC 加密**：带 Snappy 压缩的安全加密
- **IPv4 和 IPv6 支持**：完整的双栈能力 (WIP)
- **跨平台**：支持 Linux、macOS 和 Windows（包括 Windows 服务支持）
- **自动重连**：连接断开时自动重新连接
- **NAT 支持**：服务器模式内置 NAT/伪装
- **生命周期脚本**：在连接/断开事件时运行自定义脚本

## 安装

### 预编译二进制文件

从 [Releases](https://github.com/windoze/ruhop/releases) 页面下载预编译二进制文件：

| 平台 | 文件 | 说明 |
|------|------|------|
| Linux x86_64 | `ruhop-linux-amd64.tar.gz` | 独立二进制文件（musl，静态链接） |
| Linux aarch64 | `ruhop-linux-arm64.tar.gz` | 独立二进制文件（musl，静态链接） |
| Linux x86_64 | `ruhop-linux-amd64.deb` | Debian/Ubuntu 包（含 systemd 服务） |
| Linux aarch64 | `ruhop-linux-arm64.deb` | Debian/Ubuntu 包（含 systemd 服务） |
| macOS | `ruhop-macos-universal.tar.gz` | 通用二进制文件（Intel + Apple Silicon） |
| Windows | `ruhop-windows-amd64.zip` | 独立可执行文件（需自行下载 wintun.dll） |
| Windows | `ruhop-windows-amd64-setup.exe` | NSIS 安装程序（包含 wintun.dll） |

**Linux/macOS**：解压后直接运行（已保留可执行权限）：
```bash
tar -xzf ruhop-linux-amd64.tar.gz
sudo ./ruhop client -c ruhop.toml
```

**Windows**：解压 zip 文件或运行安装程序。NSIS 安装程序会自动将 `wintun.dll` 安装到 System32。

### 从源码构建

```bash
# 构建所有 crate
cargo build --release

# CLI 二进制文件位于 target/release/ruhop
```

## 快速开始

### 生成配置

```bash
./target/release/ruhop gen-config -o ruhop.toml
```

### 运行服务器

```bash
# 用你的设置编辑 ruhop.toml，然后：
sudo ./target/release/ruhop server -c ruhop.toml
```

### 运行客户端

```bash
sudo ./target/release/ruhop client -c ruhop.toml
```

### 作为 Windows 服务运行

```powershell
# 安装并启动为 Windows 服务（以管理员身份运行）
ruhop -c C:\path\to\ruhop.toml service install
ruhop service start
```

## 配置

```toml
[common]
key = "your-secret-key"          # 预共享密钥（必需）
mtu = 1400                        # MTU 大小
log_level = "info"                # 日志级别
obfuscation = false               # 启用数据包混淆
heartbeat_interval = 30           # 心跳间隔（秒）
# tun_device = "ruhop0"           # TUN 设备名称（macOS 上忽略）
# log_file = "/var/log/ruhop"     # 日志文件目录
# log_rotation = "daily"          # 日志轮转周期："hourly"、"daily"、"never"

[server]
listen = "0.0.0.0"                # 监听 IP 地址
port_range = [4096, 4196]         # 服务器监听此范围内的所有端口
tunnel_network = "10.0.0.0/24"    # 隧道网络（服务器使用第一个 IP）
# tunnel_ip = "10.0.0.1"          # 可选：覆盖服务器隧道 IP
# dns_proxy = true                # 在隧道 IP 上启用 DNS 代理
# dns_servers = ["8.8.8.8"]       # 代理的上游 DNS 服务器
max_clients = 100                 # 最大并发客户端数
enable_nat = true                 # 启用 NAT/伪装

[client]
# 单个服务器主机（无需端口 - 使用 port_range）：
server = "vpn.example.com"
# 或多个主机用于多地址服务器：
# server = ["vpn1.example.com", "vpn2.example.com", "1.2.3.4"]

port_range = [4096, 4196]         # 必须与服务器的 port_range 匹配
route_all_traffic = true          # 通过 VPN 路由所有流量
auto_reconnect = true             # 断线自动重连
reconnect_delay = 5               # 重连延迟（秒）
on_connect = "/path/to/script"    # 连接时运行的脚本
on_disconnect = "/path/to/script" # 断开时运行的脚本
```

**端口跳跃**：服务器绑定 `port_range` 中的所有端口。客户端从（主机 × 端口）组合中随机选择目标地址发送数据包。例如，2 个服务器主机和端口范围 [4096, 4196]，客户端有 202 个可能的目标地址。

## 项目结构

```
ruhop/
├── hop-dns/             # DNS 代理实现
│   └── src/
├── hop-protocol/        # 核心协议库
│   └── src/
├── hop-tun/             # TUN 设备管理
│   └── src/
├── ruhop-engine/        # VPN 引擎接口
│   └── src/
├── ruhop-cli/           # 命令行界面
│   └── src/
└── docs/
    └── PROTOCOL.md      # 协议规范
```

## Crate 说明

| Crate | 描述 |
|-------|-------------|
| [hop-dns](hop-dns/) | DNS 代理实现，用于通过 VPN 隧道处理 DNS 请求 |
| [hop-protocol](hop-protocol/) | 操作系统无关的协议库，用于数据包编解码、加密和会话管理 |
| [hop-tun](hop-tun/) | 跨平台 TUN 设备管理、路由管理和 NAT 设置 |
| [ruhop-engine](ruhop-engine/) | 高级 VPN 引擎接口，用于构建 CLI/GUI 应用 |
| [ruhop-cli](ruhop-cli/) | 运行 Ruhop VPN 的命令行界面 |

## 平台要求

### Linux

- Root 权限或以下能力：
  - `CAP_NET_ADMIN` - TUN 设备和路由管理所需
  - `CAP_NET_RAW` - TUN 设备创建所需
  - `CAP_NET_BIND_SERVICE` - DNS 代理所需（绑定 53 端口）
- 已加载 TUN 内核模块（`modprobe tun`）

无 root 运行：
```bash
sudo setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=eip' /path/to/ruhop
```

注意：
- 在非 root 权限下运行时，请确保将日志目录和控制套接字的位置更改为可写目录，否则 ruhop 将无法写入日志，且 `ruhop status` 命令将无法连接到控制套接字：
  ```
  [common]
  log_file = "/some/writable/location/ruhop"
  control_socket = "/some/writable/location/ruhop.sock"
  ```
- `iptables`、`ipset` 和/或 `nftables` 在非 root 权限下可能无法正常工作，具体取决于您的系统配置，因此在非 root 权限下运行时可能会有功能限制。

### macOS

- 直接 utun 访问需要 Root 权限

### Windows

- 管理员权限
- 已安装 WinTun 驱动（`wintun.dll` 位于 `C:\Windows\System32`）
  - 下载地址：https://www.wintun.net/
- 可选：作为 Windows 服务运行以保持持久连接

## 协议概述

GoHop 协议使用 4 阶段连接生命周期：

1. **INIT**：客户端发送 PSH（敲门）数据包以启动连接
2. **HANDSHAKE**：服务器响应 IP 分配和密钥交换
3. **WORKING**：通过加密 TUN 隧道传输数据
4. **FIN**：优雅的会话终止

### 数据包结构

```
┌──────────────────────────────────────────────────────────┐
│                       加密块                              │
├────────────┬─────────────────────────────────────────────┤
│   16 字节  │                  密文                        │
│     IV     ├─────────────────────┬───────────────────────┤
│            │    16 字节头部       │    载荷 + 噪声        │
└────────────┴─────────────────────┴───────────────────────┘
```

完整协议规范请参阅 [docs/PROTOCOL.md](docs/PROTOCOL.md)。

## 开发构建

```bash
# 构建调试版本
cargo build

# 运行测试
cargo test

# 运行 linter
cargo clippy

# 格式化代码
cargo fmt
```

## 作为库使用

### 使用 ruhop-engine

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

    // ... 等待关闭信号 ...
    let _ = shutdown_tx.send(());
    Ok(())
}
```

### 使用 hop-protocol

```rust
use hop_protocol::{Cipher, Packet, Session};

// 创建密码器
let cipher = Cipher::new(b"my-secret-key");

// 加密/解密数据
let encrypted = cipher.encrypt(plaintext)?;
let decrypted = cipher.decrypt(&encrypted)?;

// 创建数据包
let packet = Packet::data(seq, session_id, &payload);
let bytes = packet.encode();
```

### 使用 hop-tun

```rust
use hop_tun::{TunDevice, TunConfig};

let config = TunConfig::builder()
    .name("tun0")
    .ipv4("10.0.0.1", 24)
    .mtu(1400)
    .build()?;

let mut device = TunDevice::create(config).await?;

// 读写数据包
let n = device.read(&mut buf).await?;
device.write(&packet).await?;
```

## 许可证

本项目采用 GNU Affero 通用公共许可证 v3.0 或更高版本（AGPL-3.0-or-later）授权。详情请参阅 [LICENSE](LICENSE)。

## 致谢

本项目是 [GoHop](https://github.com/bigeagle/gohop) 协议的 Rust 实现，原版由 Go 语言编写。
