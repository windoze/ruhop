# hop-protocol

实现 GoHop VPN 协议的 Rust 库 - 一个支持端口跳跃的 UDP VPN，用于流量混淆。

## 概述

本 crate 提供构建 GoHop 兼容 VPN 应用的核心协议类型和功能。它是操作系统无关的，处理以下功能：

- 使用 GoHop 线路格式的数据包编解码
- 带 Snappy 压缩的 AES-256-CBC 加密
- 会话状态管理
- 数据包分片和重组
- VPN 隧道的 IP 地址池管理

## 特性

- **IPv4 和 IPv6 支持**：完整的双栈能力
- **多地址支持**：服务器可以广播多个地址用于 IP 跳跃
- **流量混淆**：可选的数据包填充和噪声注入
- **地址池管理**：VPN 隧道的动态 IP 分配

## 使用方法

添加到你的 `Cargo.toml`：

```toml
[dependencies]
hop-protocol = { path = "hop-protocol" }
```

### 加密

```rust
use hop_protocol::Cipher;

// 使用预共享密钥创建密码器
let cipher = Cipher::new(b"my-secret-key");

// 加密数据
let plaintext = b"Hello, VPN!";
let encrypted = cipher.encrypt(plaintext)?;

// 解密数据
let decrypted = cipher.decrypt(&encrypted)?;
```

### 创建数据包

```rust
use hop_protocol::{Packet, SessionId};

let sid = SessionId::random();

// 创建不同类型的数据包
let knock = Packet::knock(sid.value());
let handshake_req = Packet::handshake_request(sid.value());
let data = Packet::data(seq, sid.value(), payload);

// 编码用于传输
let bytes = packet.encode();

// 解码收到的数据包
let packet = Packet::decode(&bytes)?;
```

### 会话管理

```rust
use hop_protocol::Session;

// 客户端会话
let mut session = Session::new_client();
assert_eq!(session.state, SessionState::Init);

// 状态流转
session.start_handshake()?;
session.complete_handshake([10, 1, 1, 5], 24)?;
assert_eq!(session.state, SessionState::Working);

// 获取分配的地址
let ip = session.ip_address();
```

### IP 地址池

地址池为点对点 TUN 隧道分配地址对：

```rust
use hop_protocol::Ipv4Pool;

// 从 CIDR 创建地址池
let mut pool = Ipv4Pool::from_cidr("10.1.1.0/24")?;

// 为客户端连接分配地址对
let pair = pool.allocate()?;
// pair.client.ip     -> 10.1.1.2（客户端的 TUN 接口）
// pair.server_peer.ip -> 10.1.1.1（服务器的 TUN 端点）

// 客户端断开时释放
pool.release_pair(&pair);
```

`/24` 子网的地址分配模式：
- 对 0：server_peer=10.1.1.1，client=10.1.1.2
- 对 1：server_peer=10.1.1.3，client=10.1.1.4
- 对 2：server_peer=10.1.1.5，client=10.1.1.6
- ...

IPv6 地址池工作方式类似：

```rust
use hop_protocol::Ipv6Pool;

let mut pool = Ipv6Pool::from_cidr("2001:db8:1::/64", 10000)?;
let pair = pool.allocate()?;
```

### 完整握手示例

```rust
use hop_protocol::{Cipher, Packet, Session, SessionState, Ipv4Pool};

// 服务器设置
let cipher = Cipher::new(b"shared-secret");
let mut pool = Ipv4Pool::from_cidr("10.1.1.0/24")?;

// 接收并解密敲门数据包
let decrypted = cipher.decrypt(&received_data)?;
let packet = Packet::decode(&decrypted)?;

if packet.header.flag.is_push() {
    let sid = packet.header.sid;
    let mut session = Session::new_server(sid.into());
    session.start_handshake()?;

    // 为隧道分配地址
    let pair = pool.allocate()?;

    // 发送握手响应，包含客户端分配的 IP
    let response = Packet::handshake_response(
        sid,
        pair.client.ip.as_ipv4_bytes().unwrap(),
        pair.client.mask,
    );
    let encrypted = cipher.encrypt(&response.encode())?;
    // 发送 encrypted...

    session.complete_handshake_v2(pair.client.ip, pair.client.mask)?;
}
```

## 协议详情

完整协议规范请参阅 [PROTOCOL.md](../docs/PROTOCOL.md)。

### 数据包结构

```
+--------+--------+--------+--------+--------+--------+--------+--------+
| Byte 0 | Byte 1 | Byte 2 | Byte 3 | Byte 4 | Byte 5 | Byte 6 | Byte 7 |
+--------+--------+--------+--------+--------+--------+--------+--------+
|  Flag  |              Seq (uint32)         |      Plen (uint16)       |
+--------+--------+--------+--------+--------+--------+--------+--------+
|   FragPrefix    |  Frag  |         Sid (uint32)      |  Dlen (uint16) |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                          Payload (Dlen bytes)                         |
+-----------------------------------------------------------------------+
```

### 会话状态

1. **INIT** - 初始状态，端口敲门
2. **HANDSHAKE** - 密钥交换，IP 分配
3. **WORKING** - 数据传输中
4. **FIN** - 会话终止

### 标志值

| 标志 | 值 | 描述 |
|------|-------|-------------|
| DAT  | 0x00  | 数据包 |
| PSH  | 0x80  | 端口敲门 / 心跳 |
| HSH  | 0x40  | 握手 |
| FIN  | 0x20  | 结束会话 |
| MFR  | 0x08  | 更多分片 |
| ACK  | 0x04  | 确认 |

## 模块结构

- `address` - IP 地址类型（`IpAddress`、`AssignedAddress`、`AssignedAddresses`）
- `crypto` - 带 Snappy 压缩的 AES-256-CBC 加密（`Cipher`）
- `packet` - 数据包编解码（`Packet`、`PacketHeader`）
- `flags` - 数据包类型标志（`Flags`）
- `session` - 会话状态机（`Session`、`SessionId`、`SessionState`）
- `fragment` - 数据包分片（`FragmentAssembler`、`fragment_packet`）
- `pool` - IP 地址池管理（`Ipv4Pool`、`Ipv6Pool`、`IpPool`）
- `error` - 错误类型（`Error`、`Result`）

## 许可证

AGPL-3.0-or-later。详情请参阅 [LICENSE](../LICENSE)。
