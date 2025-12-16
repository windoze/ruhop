# ruhop-app-interface

Ruhop 的 VPN 引擎接口 - 可在 CLI 和 GUI 应用中复用。

## 概述

`ruhop-app-interface` 提供了构建 VPN 应用的高级 API。它抽象了底层协议和 TUN 设备处理的复杂性，适用于 CLI 和 GUI 应用。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                        应用层                                │
│  ┌─────────────────┐              ┌─────────────────────┐   │
│  │   ruhop-cli     │              │   未来的 GUI 应用    │   │
│  └────────┬────────┘              └──────────┬──────────┘   │
│           │                                   │              │
│           └───────────────┬──────────────────┘              │
│                           ▼                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              ruhop-app-interface                        │ │
│  │  - VpnEngine（主接口）                                  │ │
│  │  - Config（TOML 配置）                                  │ │
│  │  - Events（状态更新、错误）                              │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                        库层                                  │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  hop-protocol   │    │    hop-tun      │                │
│  │  - 加密         │    │  - TUN 设备     │                │
│  │  - 数据包       │    │  - 路由         │                │
│  │  - 会话         │    │  - NAT          │                │
│  └─────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## 安装

添加到你的 `Cargo.toml`：

```toml
[dependencies]
ruhop-app-interface = { path = "../ruhop-app-interface" }
```

## 公共 API

```rust
pub use config::{ClientConfig, Config, ServerConfig};
pub use engine::{VpnEngine, VpnRole};
pub use error::{Error, Result};
pub use event::{VpnEvent, VpnState, VpnStats};
```

## 使用方法

### 基本示例

```rust
use ruhop_app_interface::{Config, VpnEngine, VpnRole};

#[tokio::main]
async fn main() -> ruhop_app_interface::Result<()> {
    // 从 TOML 文件加载配置
    let config = Config::load("ruhop.toml")?;

    // 创建引擎（客户端或服务器模式）
    let mut engine = VpnEngine::new(config, VpnRole::Client)?;

    // 在生成任务前创建关闭句柄（用于外部控制）
    let shutdown_tx = engine.create_shutdown_handle();

    // 在后台任务中生成引擎
    let handle = tokio::spawn(async move {
        engine.start().await
    });

    // ... 等待关闭信号 ...

    // 触发优雅关闭
    let _ = shutdown_tx.send(());
    let _ = handle.await;
    Ok(())
}
```

### 自定义事件处理器

实现 `EventHandler` 来接收 VPN 生命周期通知：

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
                println!("状态: {:?} -> {:?}", old, new);
            }
            VpnEvent::Connected { tunnel_ip, .. } => {
                println!("已连接，IP: {}", tunnel_ip);
            }
            VpnEvent::Disconnected { reason } => {
                println!("已断开: {}", reason);
            }
            VpnEvent::Error { message, recoverable } => {
                eprintln!("错误 (可恢复={}): {}", recoverable, message);
            }
            VpnEvent::StatsUpdate(stats) => {
                println!("发送: {} 字节, 接收: {} 字节", stats.bytes_tx, stats.bytes_rx);
            }
            _ => {}
        }
    }
}

// 将处理器附加到引擎
let engine = VpnEngine::new(config, VpnRole::Client)?
    .with_event_handler(Arc::new(MyHandler));
```

### 查询状态和统计信息

```rust
// 获取当前状态
let state = engine.state().await;
if state.is_connected() {
    println!("VPN 已连接");
}

// 获取流量统计
let stats = engine.stats().await;
println!("运行时间: {:?}", stats.uptime);
println!("总字节数: {}", stats.total_bytes());
```

## 配置

TOML 配置包含三个部分：

```toml
[common]
key = "pre-shared-secret"
mtu = 1400
log_level = "info"
obfuscation = false
heartbeat_interval = 30

[server]
listen = "0.0.0.0:4096"
port_range = [4096, 4196]
tunnel_ip = "10.0.0.1"
tunnel_network = "10.0.0.0/24"
dns = ["8.8.8.8", "8.8.4.4"]
max_clients = 100
enable_nat = true
nat_interface = "eth0"

[client]
server = "vpn.example.com:4096"
port_range = [4096, 4196]
tunnel_ip = "10.0.0.5"            # 可选：请求特定 IP
route_all_traffic = true
excluded_routes = ["192.168.1.0/24"]
dns = ["8.8.8.8"]
auto_reconnect = true
max_reconnect_attempts = 0        # 0 = 无限制
reconnect_delay = 5
on_connect = "/path/to/connect.sh"
on_disconnect = "/path/to/disconnect.sh"
```

### 配置加载

```rust
use ruhop_app_interface::Config;

// 从文件加载
let config = Config::load("ruhop.toml")?;

// 从字符串解析
let config = Config::from_toml(toml_content)?;

// 生成示例配置
let sample = Config::sample();

// 访问角色特定配置
let server_cfg = config.server_config()?;
let client_cfg = config.client_config()?;
```

## VPN 状态

| 状态 | 描述 |
|-------|-------------|
| `Disconnected` | 未运行 |
| `Connecting` | 正在启动 |
| `Handshaking` | 正在进行密钥交换 |
| `Connected` | 运行中，隧道活跃 |
| `Reconnecting` | 断线后自动重连中 |
| `Disconnecting` | 正在优雅关闭 |
| `Error` | 错误状态 |

### 状态方法

```rust
let state = engine.state().await;

state.is_active();     // 如果是 connecting、handshaking、connected 或 reconnecting 返回 true
state.is_connected();  // 仅当 Connected 时返回 true
state.description();   // 人类可读的描述
```

## VPN 事件

| 事件 | 描述 |
|-------|-------------|
| `StateChanged { old, new }` | 状态机转换 |
| `Connected { tunnel_ip, peer_ip }` | 连接已建立 |
| `Disconnected { reason }` | 连接已终止 |
| `ClientConnected { session_id, assigned_ip }` | 服务器：新客户端连接 |
| `ClientDisconnected { session_id, reason }` | 服务器：客户端断开 |
| `StatsUpdate(VpnStats)` | 流量统计 |
| `Error { message, recoverable }` | 错误通知 |
| `Log { level, message }` | 日志消息 |

## VPN 统计信息

```rust
pub struct VpnStats {
    pub bytes_rx: u64,           // 接收字节数
    pub bytes_tx: u64,           // 发送字节数
    pub packets_rx: u64,         // 接收数据包数
    pub packets_tx: u64,         // 发送数据包数
    pub uptime: Duration,        // 连接时长
    pub active_sessions: usize,  // 服务器：活跃客户端会话数
    pub last_rx: Option<Instant>,
    pub last_tx: Option<Instant>,
}
```

## 生命周期脚本

客户端支持 `on_connect` 和 `on_disconnect` 脚本，接收以下参数：

```
<脚本> <本地IP> <对端IP> <前缀长度> <TUN设备>
```

连接脚本示例：

```bash
#!/bin/bash
LOCAL_IP=$1
PEER_IP=$2
PREFIX=$3
TUN_DEV=$4

echo "已连接: $LOCAL_IP 通过 $TUN_DEV"
# 添加自定义路由、更新 DNS 等
```

## 关键引擎方法

| 方法 | 描述 |
|--------|-------------|
| `VpnEngine::new(config, role)` | 创建引擎实例 |
| `.with_event_handler(handler)` | 设置自定义事件处理器 |
| `.create_shutdown_handle()` | 获取用于关闭的广播发送器 |
| `.shutdown_handle()` | 获取现有的关闭句柄 |
| `.start().await` | 启动 VPN |
| `.stop().await` | 停止 VPN |
| `.state().await` | 获取当前 VPN 状态 |
| `.stats().await` | 获取流量统计 |

## 错误类型

```rust
pub enum Error {
    Config(String),           // 配置错误
    ConfigParse(toml::Error), // TOML 解析错误
    Io(std::io::Error),       // I/O 错误
    Protocol(hop_protocol::Error),
    Tun(hop_tun::Error),
    Connection(String),       // 连接错误
    Auth(String),             // 认证错误
    Timeout(String),          // 超时错误
    Session(String),          // 会话错误
    AlreadyRunning,           // 引擎已在运行
    NotRunning,               // 引擎未运行
    Shutdown,                 // 正在关闭
    InvalidState(String),     // 无效的状态转换
    AddressAllocation(String),// IP 分配错误
    Script(String),           // 脚本执行错误
}

// 辅助方法
error.is_recoverable();    // 可以重试？
error.is_config_error();   // 配置问题？
```

## 模块结构

- `config` - TOML 配置解析（`Config`、`ServerConfig`、`ClientConfig`）
- `engine` - VPN 引擎实现（`VpnEngine`、`VpnRole`）
- `event` - 事件类型和处理器 trait（`VpnEvent`、`VpnState`、`VpnStats`、`EventHandler`）
- `script` - 生命周期脚本执行（`ScriptParams`、`run_script`）
- `error` - 错误类型（`Error`、`Result`）

## 许可证

AGPL-3.0-or-later。详情请参阅 [LICENSE](../LICENSE)。
