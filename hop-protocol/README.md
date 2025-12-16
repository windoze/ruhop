# hop-protocol

A Rust library implementing the GoHop VPN protocol - a UDP-based VPN with port hopping capabilities for traffic obfuscation.

## Overview

This crate provides the core protocol types and functionality for building GoHop-compatible VPN applications. It is OS-independent and handles:

- Packet encoding/decoding with the GoHop wire format
- AES-256-CBC encryption with Snappy compression
- Session state management
- Packet fragmentation and reassembly
- IP address pool management for VPN tunnels

## Features

- **IPv4 and IPv6 support**: Full dual-stack capability
- **Multi-address support**: Servers can advertise multiple addresses for IP hopping
- **Traffic obfuscation**: Optional packet padding and noise injection
- **Address pool management**: Dynamic IP allocation for VPN tunnels

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
hop-protocol = { path = "hop-protocol" }
```

### Encryption

```rust
use hop_protocol::Cipher;

// Create cipher with pre-shared key
let cipher = Cipher::new(b"my-secret-key");

// Encrypt data
let plaintext = b"Hello, VPN!";
let encrypted = cipher.encrypt(plaintext)?;

// Decrypt data
let decrypted = cipher.decrypt(&encrypted)?;
```

### Packet Creation

```rust
use hop_protocol::{Packet, SessionId};

let sid = SessionId::random();

// Create different packet types
let knock = Packet::knock(sid.value());
let handshake_req = Packet::handshake_request(sid.value());
let data = Packet::data(seq, sid.value(), payload);

// Encode for transmission
let bytes = packet.encode();

// Decode received packet
let packet = Packet::decode(&bytes)?;
```

### Session Management

```rust
use hop_protocol::Session;

// Client session
let mut session = Session::new_client();
assert_eq!(session.state, SessionState::Init);

// Progress through states
session.start_handshake()?;
session.complete_handshake([10, 1, 1, 5], 24)?;
assert_eq!(session.state, SessionState::Working);

// Get assigned address
let ip = session.ip_address();
```

### IP Address Pool

The pool allocates address pairs for point-to-point TUN tunnels:

```rust
use hop_protocol::Ipv4Pool;

// Create pool from CIDR
let mut pool = Ipv4Pool::from_cidr("10.1.1.0/24")?;

// Allocate address pair for a client connection
let pair = pool.allocate()?;
// pair.client.ip     -> 10.1.1.2 (client's TUN interface)
// pair.server_peer.ip -> 10.1.1.1 (server's TUN endpoint)

// Release when client disconnects
pool.release_pair(&pair);
```

Address allocation pattern for a `/24` subnet:
- Pair 0: server_peer=10.1.1.1, client=10.1.1.2
- Pair 1: server_peer=10.1.1.3, client=10.1.1.4
- Pair 2: server_peer=10.1.1.5, client=10.1.1.6
- ...

IPv6 pools work similarly:

```rust
use hop_protocol::Ipv6Pool;

let mut pool = Ipv6Pool::from_cidr("2001:db8:1::/64", 10000)?;
let pair = pool.allocate()?;
```

### Full Handshake Example

```rust
use hop_protocol::{Cipher, Packet, Session, SessionState, Ipv4Pool};

// Server setup
let cipher = Cipher::new(b"shared-secret");
let mut pool = Ipv4Pool::from_cidr("10.1.1.0/24")?;

// Receive and decrypt knock packet
let decrypted = cipher.decrypt(&received_data)?;
let packet = Packet::decode(&decrypted)?;

if packet.header.flag.is_push() {
    let sid = packet.header.sid;
    let mut session = Session::new_server(sid.into());
    session.start_handshake()?;

    // Allocate addresses for the tunnel
    let pair = pool.allocate()?;

    // Send handshake response with client's assigned IP
    let response = Packet::handshake_response(
        sid,
        pair.client.ip.as_ipv4_bytes().unwrap(),
        pair.client.mask,
    );
    let encrypted = cipher.encrypt(&response.encode())?;
    // send encrypted...

    session.complete_handshake_v2(pair.client.ip, pair.client.mask)?;
}
```

## Protocol Details

See [PROTOCOL.md](../docs/PROTOCOL.md) for the full protocol specification.

### Packet Structure

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

### Session States

1. **INIT** - Initial state, port knocking
2. **HANDSHAKE** - Key exchange, IP assignment
3. **WORKING** - Data transfer active
4. **FIN** - Session terminating

### Flag Values

| Flag | Value | Description |
|------|-------|-------------|
| DAT  | 0x00  | Data packet |
| PSH  | 0x80  | Port knock / Heartbeat |
| HSH  | 0x40  | Handshake |
| FIN  | 0x20  | Finish session |
| MFR  | 0x08  | More fragments |
| ACK  | 0x04  | Acknowledgment |

## Module Structure

- `address` - IP address types (`IpAddress`, `AssignedAddress`, `AssignedAddresses`)
- `crypto` - AES-256-CBC encryption with Snappy compression (`Cipher`)
- `packet` - Packet encoding/decoding (`Packet`, `PacketHeader`)
- `flags` - Packet type flags (`Flags`)
- `session` - Session state machine (`Session`, `SessionId`, `SessionState`)
- `fragment` - Packet fragmentation (`FragmentAssembler`, `fragment_packet`)
- `pool` - IP address pool management (`Ipv4Pool`, `Ipv6Pool`, `IpPool`)
- `error` - Error types (`Error`, `Result`)

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
