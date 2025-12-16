# hop-tun

用于 VPN 实现的跨平台 TUN 设备管理。

## 概述

`hop-tun` 提供了一个统一的 API，用于在 Linux、macOS 和 Windows 上创建和管理 TUN 设备，以及路由管理和 NAT 设置。

## 特性

- **TUN 设备管理**：创建、配置和删除 TUN 接口
- **路由管理**：添加/删除路由，配置默认网关
- **NAT/伪装**：设置 NAT 规则用于流量转发
- **异步支持**：支持 Tokio 和 async-std 运行时
- **跨平台**：支持 Linux、macOS 和 Windows
- **NetworkExtension 支持**：集成 macOS/iOS NetworkExtension 框架

## 安装

添加到你的 `Cargo.toml`：

```toml
[dependencies]
hop-tun = { path = "../hop-tun" }
```

## Feature 标志

| Feature | 默认 | 描述 |
|---------|---------|-------------|
| `async-tokio` | 是 | 通过 Tokio 运行时提供异步支持 |
| `async-std` | 否 | 通过 async-std 运行时提供异步支持 |
| `network-extension` | 否 | macOS/iOS NetworkExtension 框架绑定 |

## 平台要求

### Linux

- Root 权限或 `CAP_NET_ADMIN` 能力
- 已加载 TUN 内核模块（`modprobe tun`）

### macOS

**开发/测试（直接 utun）**：
- Root 权限
- 无需额外设置

**生产应用（NetworkExtension）**：
- Packet Tunnel Provider 应用扩展
- `com.apple.developer.networking.networkextension` 授权
- 详情请参阅 `macos` 模块

### Windows

- 管理员权限
- 已安装 WinTun 驱动（https://www.wintun.net/）

## 公共 API

```rust
// 核心类型
pub use TunConfig, TunConfigBuilder;  // 配置
pub use TunDevice;                     // TUN 设备
pub use Route, RouteManager;           // 路由管理
pub use NatManager;                    // NAT 管理
pub use Error, Result;                 // 错误处理

// 平台特定（Unix + async-tokio）
pub use BorrowedTunDevice;             // 用于 NetworkExtension 集成
```

## 使用方法

### 创建 TUN 设备

```rust
use hop_tun::{TunDevice, TunConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建配置
    let config = TunConfig::builder()
        .name("tun0")
        .ipv4("10.0.0.1", 24)
        .mtu(1400)
        .build()?;

    // 创建设备
    let mut device = TunDevice::create(config).await?;

    // 读取数据包
    let mut buf = vec![0u8; 2000];
    let n = device.read(&mut buf).await?;
    println!("收到 {} 字节", n);

    // 写入数据包
    device.write(&packet_data).await?;

    Ok(())
}
```

### 配置选项

```rust
use hop_tun::TunConfig;

let config = TunConfig::builder()
    .name("utun5")                    // 设备名（某些平台可选）
    .ipv4("10.0.0.1", 24)             // IPv4 地址和前缀长度
    .ipv6("fd00::1", 64)              // IPv6 地址（可选）
    .mtu(1400)                        // MTU 大小
    .build()?;
```

### 路由管理

```rust
use hop_tun::{Route, RouteManager};
use std::net::Ipv4Addr;

let mut route_manager = RouteManager::new()?;

// 添加通过 TUN 设备的路由
let route = Route::new(
    "10.1.0.0".parse()?,
    24,
    Some("10.0.0.1".parse()?),  // 网关
    Some("tun0".to_string()),    // 接口
);
route_manager.add(&route).await?;

// 删除路由
route_manager.remove(&route).await?;
```

### NAT 管理

```rust
use hop_tun::NatManager;

let mut nat = NatManager::new()?;

// 为隧道网络启用 NAT
nat.enable(
    "10.0.0.0/24",           // 源网络
    "eth0",                   // 出站接口
).await?;

// 禁用 NAT
nat.disable().await?;
```

### macOS NetworkExtension 集成

对于使用 NetworkExtension 的生产 macOS/iOS 应用：

```rust
#[cfg(all(target_os = "macos", feature = "network-extension"))]
use hop_tun::macos::{PacketTunnelBridge, NEPacketTunnelFlow};

// 在你的 PacketTunnelProvider 实现中：
let bridge = PacketTunnelBridge::new(packet_flow);

// 从隧道读取数据包
let packets = bridge.read_packets().await?;

// 向隧道写入数据包
bridge.write_packets(&packets).await?;
```

## 模块结构

- `config` - TUN 设备配置（`TunConfig`、`TunConfigBuilder`）
- `device` - TUN 设备抽象（`TunDevice`、`BorrowedTunDevice`）
- `route` - 路由管理（`Route`、`RouteManager`）
- `nat` - NAT/伪装设置（`NatManager`）
- `error` - 错误类型（`Error`、`Result`）
- `linux` - Linux 特定实现
- `macos` - macOS 特定实现（utun、NetworkExtension）
- `windows` - Windows 特定实现（WinTun）

## 常量

```rust
pub const DEFAULT_MTU: u16 = 1400;      // 默认 MTU
pub const MAX_PACKET_SIZE: usize = 65535; // 最大数据包大小
```

## 平台特定说明

### Linux

通过 `/dev/net/tun` 使用内核 TUN/TAP 驱动。路由管理使用 rtnetlink 进行高效的内核通信。

### macOS

两种运行模式：

1. **直接 utun**：用于开发和 CLI 工具。需要 root 权限。
2. **NetworkExtension**：用于 App Store 应用。需要适当的授权和 Packet Tunnel Provider 扩展。

### Windows

使用 WinTun 驱动（https://www.wintun.net/）。使用前必须安装该驱动。

## 错误处理

```rust
use hop_tun::{Error, Result};

fn example() -> Result<()> {
    let config = TunConfig::builder()
        .ipv4("10.0.0.1", 24)
        .build()
        .map_err(|e| Error::Config(e.to_string()))?;

    // 错误变体：
    // - Error::Config - 配置错误
    // - Error::Io - I/O 错误
    // - Error::Permission - 权限不足
    // - Error::NotFound - 设备未找到
    // - Error::Platform - 平台特定错误

    Ok(())
}
```

## 许可证

AGPL-3.0-or-later。详情请参阅 [LICENSE](../LICENSE)。
