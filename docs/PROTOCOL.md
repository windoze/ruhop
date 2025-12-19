# GoHop Protocol Specification

This document describes the GoHop VPN protocol in detail.

## Overview

GoHop uses a custom UDP-based protocol with the following characteristics:
- Pre-shared key authentication
- AES-256-CBC encryption with Snappy compression
- Port hopping across a configurable range
- Stateful connection with handshake, working, and finish phases

## Packet Format

### Wire Format

Every packet transmitted over UDP has the following structure:

```
+------------------+------------------------+
|   IV (16 bytes)  |  Encrypted Payload     |
+------------------+------------------------+
```

- **IV**: 16-byte random initialization vector for AES-CBC
- **Encrypted Payload**: AES-256-CBC encrypted, Snappy-compressed data

### Decrypted Packet Structure

After decryption and decompression, packets have this structure:

```
+--------+--------+--------+--------+--------+--------+--------+--------+
| Byte 0 | Byte 1 | Byte 2 | Byte 3 | Byte 4 | Byte 5 | Byte 6 | Byte 7 |
+--------+--------+--------+--------+--------+--------+--------+--------+
|  Flag  |              Seq (uint32, big-endian)       |  Plen (uint16) |
+--------+--------+--------+--------+--------+--------+--------+--------+

+--------+--------+--------+--------+--------+--------+--------+--------+
| Byte 8 | Byte 9 | Byte10 | Byte11 | Byte12 | Byte13 | Byte14 | Byte15 |
+--------+--------+--------+--------+--------+--------+--------+--------+
|   FragPrefix    |  Frag  |         Sid (uint32)      |  Dlen (uint16) |
+--------+--------+--------+--------+--------+--------+--------+--------+

+--------+--------+--------+--------+--------+
| Byte16 | Byte17 |  ...   |        |        |
+--------+--------+--------+--------+--------+
|              Payload (Dlen bytes)          |
+--------------------------------------------+
|              Noise (optional)              |
+--------------------------------------------+
```

### Header Fields (16 bytes total)

| Field | Size | Description |
|-------|------|-------------|
| Flag | 1 byte | Packet type flags (see below) |
| Seq | 4 bytes | Sequence number (big-endian) |
| Plen | 2 bytes | Total payload length (for fragmentation) |
| FragPrefix | 2 bytes | Fragment offset in original payload |
| Frag | 1 byte | Fragment index |
| Sid | 4 bytes | Session ID |
| Dlen | 2 bytes | Actual data length in this packet |

### Flag Values

Flags can be combined using bitwise OR:

| Flag | Value | Description |
|------|-------|-------------|
| HOP_FLG_DAT | 0x00 | Data packet |
| HOP_FLG_PSH | 0x80 | Port knock / Heartbeat |
| HOP_FLG_HSH | 0x40 | Handshake |
| HOP_FLG_FIN | 0x20 | Finish session |
| HOP_FLG_PRB | 0x10 | Probe (for path loss detection) |
| HOP_FLG_MFR | 0x08 | More fragments follow |
| HOP_FLG_ACK | 0x04 | Acknowledgment |

Common flag combinations:
- `0x00` (HOP_FLG_DAT): Data packet
- `0x08` (HOP_FLG_DAT | HOP_FLG_MFR): Fragmented data, more to follow
- `0x80` (HOP_FLG_PSH): Port knock or heartbeat request
- `0x84` (HOP_FLG_PSH | HOP_FLG_ACK): Heartbeat acknowledgment
- `0x40` (HOP_FLG_HSH): Handshake request
- `0x44` (HOP_FLG_HSH | HOP_FLG_ACK): Handshake acknowledgment
- `0x60` (HOP_FLG_HSH | HOP_FLG_FIN): Handshake error/rejection
- `0x20` (HOP_FLG_FIN): Finish session request
- `0x24` (HOP_FLG_FIN | HOP_FLG_ACK): Finish acknowledgment
- `0x10` (HOP_FLG_PRB): Probe request (client → server)
- `0x14` (HOP_FLG_PRB | HOP_FLG_ACK): Probe response (server → client)

## Encryption

### Key Derivation

The pre-shared key is padded to 32 bytes using PKCS5 padding for AES-256:

```
key = PKCS5Padding(pre_shared_key, 32)
```

### Encryption Process

1. Generate 16 random bytes for IV
2. Compress plaintext using Snappy
3. Pad compressed data to 16-byte boundary (PKCS5)
4. Encrypt with AES-256-CBC using IV
5. Prepend IV to ciphertext

### Decryption Process

1. Extract first 16 bytes as IV
2. Decrypt remaining bytes with AES-256-CBC
3. Remove PKCS5 padding
4. Decompress with Snappy

## Session States

```
+------------+     knock      +---------------+
|            | -------------> |               |
|  INIT (0)  |                | HANDSHAKE (1) |
|            | <------------- |               |
+------------+    timeout     +---------------+
                                    |
                              handshake_ack
                                    |
                                    v
+------------+     FIN        +---------------+
|            | <------------- |               |
|  FIN (3)   |                | WORKING (2)   |
|            | -------------> |               |
+------------+    FIN_ACK     +---------------+
```

| State | Value | Description |
|-------|-------|-------------|
| HOP_STAT_INIT | 0 | Initial state, not connected |
| HOP_STAT_HANDSHAKE | 1 | Handshake in progress |
| HOP_STAT_WORKING | 2 | Session established, data transfer active |
| HOP_STAT_FIN | 3 | Session terminating |

## Connection Establishment

### Port Knocking Phase

Before handshaking, the client sends knock packets to multiple server ports to establish address mappings:

1. Client generates random 4-byte session ID (SID)
2. Client sends PSH packets to each port in the hop range
3. Server records client addresses for each port

**Knock Packet (Client -> Server):**
```
Flag: HOP_FLG_PSH (0x80)
Payload: SID (4 bytes)
```

**Knock Response (Server -> Client, if session exists):**
```
Flag: HOP_FLG_PSH | HOP_FLG_ACK (0x84)
Payload: [1 byte]
```

### Handshake Phase

After knocking, client initiates handshake:

**Handshake Request (Client -> Server):**
```
Flag: HOP_FLG_HSH (0x40)
Payload: SID (4 bytes)
```

**Handshake Response (Server -> Client):**
```
Flag: HOP_FLG_HSH | HOP_FLG_ACK (0x44)
Payload:
  - Protocol Version (1 byte): 0x03
  - Address Count (1 byte): Number of addresses (1-255)
  - For each address:
    - IP Type (1 byte): 0x04 for IPv4, 0x06 for IPv6
    - IP Address (4 or 16 bytes): e.g., 10.1.1.3 (IPv4) or 2001:db8::1 (IPv6)
    - Subnet Mask/Prefix (1 byte): e.g., 24 for IPv4, 64 for IPv6
```

The first address is the primary address used for TUN interface configuration.
Additional addresses enable IP hopping - the client can send packets to any of
the server's advertised IP addresses for improved obfuscation.

**Handshake Confirmation (Client -> Server):**
```
Flag: HOP_FLG_HSH | HOP_FLG_ACK (0x44)
Payload: SID (4 bytes)
```

**Handshake Error (Server -> Client):**
```
Flag: HOP_FLG_HSH | HOP_FLG_FIN (0x60)
Payload: Error message (string)
```

### Handshake Timeout

- Server retries handshake response up to 5 times with 2-second intervals
- Client retries knock/handshake with random delays (0-1000ms between attempts)
- If no response after 5 retries, server kicks the peer

## Data Transfer

Once in WORKING state, IP packets are tunneled:

**Data Packet:**
```
Flag: HOP_FLG_DAT (0x00)
Seq: Incrementing sequence number
Sid: Session ID
Dlen: Length of IP packet
Payload: Raw IP packet from tun interface
```

### Port and IP Hopping

Port hopping is the core obfuscation mechanism in GoHop. Both client and server randomly select destination addresses for each packet, making traffic analysis difficult.

#### Address Pool Generation

The client generates an address pool from the configuration:

```
Address Pool = Server IPs × Port Range
```

Example with 3 server IPs and ports 4096-4100:
```
server = ["203.0.113.1", "203.0.113.2", "198.51.100.1"]
port_range = [4096, 4100]

Address Pool (15 addresses):
  203.0.113.1:4096,  203.0.113.1:4097,  203.0.113.1:4098,  203.0.113.1:4099,  203.0.113.1:4100
  203.0.113.2:4096,  203.0.113.2:4097,  203.0.113.2:4098,  203.0.113.2:4099,  203.0.113.2:4100
  198.51.100.1:4096, 198.51.100.1:4097, 198.51.100.1:4098, 198.51.100.1:4099, 198.51.100.1:4100
```

#### Client Sending Behavior

For **every packet** sent (including knock, handshake, data, heartbeat, and FIN packets), the client:

1. Randomly selects an address from the pool
2. Sends the packet to that address
3. The next packet may go to a completely different address

```
Client                                              Server
   |                                                   |
   |-- Knock -----> 203.0.113.1:4097 ---------------->|
   |-- Knock -----> 198.51.100.1:4099 --------------->|
   |-- Knock -----> 203.0.113.2:4096 ---------------->|
   |-- Handshake -> 203.0.113.1:4100 ---------------->|
   |<-------------- Handshake ACK --------------------|
   |-- Confirm ---> 198.51.100.1:4097 --------------->|
   |-- Data ------> 203.0.113.2:4098 ---------------->|
   |-- Data ------> 203.0.113.1:4096 ---------------->|
   |<-------------- Data -----------------------------|
   |-- Data ------> 198.51.100.1:4100 --------------->|
   |                                                   |
```

#### Server Socket Architecture

The server binds **one UDP socket per port** in the configured range:

```
[server]
listen = "0.0.0.0"
port_range = [4096, 4100]

Creates 5 sockets:
  Socket 0: 0.0.0.0:4096
  Socket 1: 0.0.0.0:4097
  Socket 2: 0.0.0.0:4098
  Socket 3: 0.0.0.0:4099
  Socket 4: 0.0.0.0:4100
```

Each socket runs an independent receive loop. The socket index is tracked per-client session.

#### Multi-Homed Server NAT Traversal

When a server has multiple IP addresses (multi-homed), proper NAT traversal requires responding from the same local IP that received the request.

**Problem**: Without tracking, responses might go out from the wrong source IP:
```
Client sends to: 203.0.113.1:4097 (external) → 10.0.0.1:4097 (internal via DNAT)
Server responds from: 10.0.0.2:4097 (wrong internal IP) → 203.0.113.2:4097 (wrong external via SNAT)
Client's NAT drops the packet (unexpected source)
```

**Solution**: Server uses `IP_PKTINFO` (Linux) or `IP_RECVDSTADDR` (macOS) to track the destination IP of incoming packets:

```
1. Client sends packet to 203.0.113.1:4097
2. Cloud DNAT translates to 10.0.0.1:4097
3. Server receives packet, kernel reports local_addr = 10.0.0.1:4097
4. Server stores last_recv_local_addr = 10.0.0.1:4097 for this session
5. Server sends response using sendmsg() with IP_PKTINFO to force source = 10.0.0.1
6. Cloud SNAT translates back to 203.0.113.1:4097
7. Client receives response from expected address
```

#### Session Address Tracking

The server tracks per-client session:

| Field | Description |
|-------|-------------|
| `peer_addr` | Client's current source address (IP:port) |
| `last_recv_socket_idx` | Index of socket that last received from this client |
| `last_recv_local_addr` | Local IP:port that received the last packet |

These fields are updated on **every received packet** to handle:
- Client's source port changes (NAT rebinding)
- Client hopping between different server IPs
- Proper response routing for multi-homed servers

#### Server Response Behavior

When the server sends packets back to a client (data, heartbeat ACK, etc.):

1. Uses the socket at `last_recv_socket_idx`
2. Sends from `last_recv_local_addr.ip()` for multi-homed NAT traversal
3. Sends to `peer_addr` (client's last known address)

This ensures responses go out from the same IP that received the most recent packet from that client.

#### Traffic Pattern

A typical session shows packets distributed across addresses:

```
Time    Direction   Address                 Packet Type
----    ---------   -------                 -----------
0.000   C→S        203.0.113.1:4097        Knock
0.001   C→S        198.51.100.1:4099       Knock
0.002   C→S        203.0.113.2:4096        Knock
0.010   C→S        203.0.113.1:4100        Handshake
0.095   S→C        203.0.113.1:4100        Handshake ACK
0.096   C→S        198.51.100.1:4097       Handshake Confirm
0.100   C→S        203.0.113.2:4098        Data
0.102   S→C        203.0.113.2:4098        Data
0.150   C→S        203.0.113.1:4096        Data
0.152   S→C        203.0.113.1:4096        Data
0.200   C→S        198.51.100.1:4100       Data
...
```

#### Benefits

1. **Traffic Analysis Resistance**: Observers see packets to many different addresses
2. **Port Blocking Evasion**: If one port is blocked, others still work
3. **IP Blocking Resilience**: Multiple server IPs provide redundancy
4. **NAT Mapping Diversity**: Different source ports reduce fingerprinting

### Packet Ordering

- Receiver maintains ordered buffer based on sequence numbers
- Packets are reordered before delivery to tun interface
- Buffer waits briefly for out-of-order packets before flushing

## Heartbeat / Keep-Alive

Server initiates heartbeats to detect dead peers:

**Heartbeat Request (Server -> Client):**
```
Flag: HOP_FLG_PSH (0x80)
Payload: (empty)
```

**Heartbeat Response (Client -> Server):**
```
Flag: HOP_FLG_PSH | HOP_FLG_ACK (0x84)
Payload: SID (4 bytes)
```

- Server sends heartbeat every `PeerTimeout/2` seconds
- Peer is kicked if no response within `PeerTimeout` seconds
- Client sends periodic knocks as keep-alive (configurable `heartbeat-interval`)

## Path Loss Detection (Optional)

When enabled, the client probes each server address to detect blocked or lossy network paths. Addresses with high packet loss are temporarily blacklisted.

### Probe Mechanism

The client sends probe packets to each address in the pool in round-robin fashion:

**Probe Request (Client -> Server):**
```
Flag: HOP_FLG_PRB (0x10)
Seq: Probe ID (for correlation)
Sid: Session ID
Payload: timestamp_ms (8 bytes, big-endian) for RTT measurement
```

**Probe Response (Server -> Client):**
```
Flag: HOP_FLG_PRB | HOP_FLG_ACK (0x14)
Seq: Probe ID (echoed)
Sid: Session ID
Payload: timestamp_ms (8 bytes, echoed from request)
```

### Loss Detection Flow

```
Client                                              Server
   |                                                   |
   |-- Probe (id=1) --> 203.0.113.1:4097 ------------>|
   |<-- Probe ACK (id=1) -----------------------------|
   |                                                   |
   |-- Probe (id=2) --> 198.51.100.1:4099 ----------->|
   |                    (no response - blocked)        |
   |                                                   |
   |-- Probe (id=3) --> 203.0.113.2:4096 ------------>|
   |<-- Probe ACK (id=3) -----------------------------|
   |                                                   |
```

### Blacklisting

- Client tracks probes sent and responses received per address
- After `min_probes` probes, if loss rate >= `threshold`, address is blacklisted
- Blacklisted addresses are skipped when selecting targets for data packets
- After `blacklist_duration`, address is re-probed and may recover

### Configuration

```toml
[client.probe]
interval = 10            # Probe each address every 10 seconds
threshold = 0.5          # Blacklist if >= 50% loss
blacklist_duration = 300 # Keep blacklisted for 5 minutes
min_probes = 3           # Require 3 probes before deciding
```

### Benefits

1. **Automatic failover**: Traffic avoids blocked ports/IPs
2. **Self-healing**: Recovered paths are automatically re-enabled
3. **Low overhead**: Small probe packets (24 bytes) sent infrequently

## Session Termination

Either side can initiate termination:

**Finish Request:**
```
Flag: HOP_FLG_FIN (0x20)
Payload: SID (4 bytes)
```

**Finish Acknowledgment:**
```
Flag: HOP_FLG_FIN | HOP_FLG_ACK (0x24)
Payload: (empty)
```

- FIN packets are sent multiple times (3x) for reliability
- Server releases assigned IP back to pool
- Client cleans up routes and interface

## Fragmentation (Disabled)

The protocol supports packet fragmentation for traffic morphing, but it's currently disabled:

**Fragment Packet:**
```
Flag: HOP_FLG_DAT | HOP_FLG_MFR (0x08) for non-final fragments
      HOP_FLG_DAT (0x00) for final fragment
Plen: Total original payload length
FragPrefix: Offset of this fragment in original payload
Frag: Fragment index (0, 1, 2, ...)
Dlen: Length of this fragment's data
```

Reassembly uses sequence number to correlate fragments.

## Session Identification

Sessions are identified by a routing key:
- For IPv4: 64-bit key (Upper 32 bits: SID, Lower 32 bits: IPv4 address)
- For IPv6: 128-bit key (SID XORed into upper 32 bits of IPv6 address)

Server maintains two mappings per peer:
1. SID-based key for control packets (knock, handshake, heartbeat)
2. IP-based key for data packet routing

## Noise Injection

Packets can include random noise bytes after the payload:
- Noise is added for traffic analysis resistance
- Noise length is random (0 to MTU-64-payload_length)
- Noise is not included in Dlen, only actual payload is

## Packet Obfuscation (Optional)

When packet obfuscation is enabled, additional padding is applied to obscure traffic patterns:

### Wire Format with Obfuscation

```
+------------------+------------------------+------------------+
| Post-pad (0-15)  |   IV (16 bytes)        | Encrypted data   |
+------------------+------------------------+------------------+
```

### Pre-compression Padding

Random padding bytes are appended **after** the packet data, **before** compression:

```
+------------------+------------------+
| Packet data      | Random pad (0-N) |
+------------------+------------------+
         |
         v  (Snappy compression)
+--------------------+
| Compressed data    |
+--------------------+
```

- Random bytes (0-N, where N is configurable, default 16) are appended after the packet data
- No length prefix is needed because the packet header contains `Dlen` which tells the receiver the actual payload length
- After decompression, `Packet::decode()` uses `Dlen` to extract only the actual payload, ignoring trailing padding
- The padded data is then compressed and encrypted with AES-256-CBC

### Post-encryption Padding

Random bytes (0 to 15) are prepended before the IV to make the total packet length non-block-aligned:

- Without obfuscation: `IV (16) + ciphertext (multiple of 16)` = always block-aligned
- With obfuscation: `random (0-15) + IV (16) + ciphertext` = usually non-aligned

The padding length is determined during decryption by: `total_len % 16`
Since IV is 16 bytes and ciphertext is block-aligned, any remainder must be padding.

### Obfuscation Benefits

1. **Data length obfuscation**: Pre-encryption padding masks the actual payload size
2. **Encrypted length obfuscation**: Post-encryption padding breaks the block-alignment pattern
3. **Traffic analysis resistance**: Combined with noise injection, packet sizes become unpredictable
4. **Zero overhead for decoding**: No length prefix needed - existing header fields handle it

## Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| HOP_HDR_LEN | 16 | Header size in bytes |
| HOP_PROTO_VERSION | 0x03 | Current protocol version (with multi-address support) |
| IP_TYPE_V4 | 0x04 | IPv4 address type marker |
| IP_TYPE_V6 | 0x06 | IPv6 address type marker |
| cipherBlockSize | 16 | AES block size (IV size) |
| Default MTU | 1400 | Maximum transmission unit |
| IFACE_BUFSIZE | 2000 | Interface read buffer size |

## Security Considerations

1. **Pre-shared Key**: All security depends on key secrecy
2. **No Forward Secrecy**: Compromise of PSK exposes all past traffic
3. **No Replay Protection**: Sequence numbers aren't cryptographically verified
4. **IV Reuse Risk**: Random IV generation; collision probability exists
5. **No Authentication**: MAC not included; relies on Snappy decompression failure for integrity

## Example Message Flow

### IPv4 Example
```
Client                                          Server
   |                                               |
   |-------- PSH (knock, port 4001) ------------->>|
   |-------- PSH (knock, port 4002) ------------->>|
   |-------- PSH (knock, port 4003) ------------->>|
   |                    ...                        |
   |                                               |
   |-------- HSH (handshake request) ----------->>|
   |                                               |
   |<<------- HSH|ACK (IP: 10.1.1.3/24) -----------|
   |                                               |
   |-------- HSH|ACK (confirm) ----------------->>|
   |                                               |
   |<<============ DATA (IP packets) =============>>|
   |                                               |
   |<<------- PSH (heartbeat) ---------------------|
   |-------- PSH|ACK (heartbeat response) ------>>|
   |                                               |
   |-------- FIN (terminate) ------------------->>|
   |<<------- FIN|ACK (acknowledge) ---------------|
   |                                               |
```

### IPv6 Example
```
Client                                          Server
   |                                               |
   |-------- PSH (knock, port 4001) ------------->>|
   |-------- PSH (knock, port 4002) ------------->>|
   |                    ...                        |
   |                                               |
   |-------- HSH (handshake request) ----------->>|
   |                                               |
   |<<-- HSH|ACK (IP: 2001:db8::100/64) -----------|
   |                                               |
   |-------- HSH|ACK (confirm) ----------------->>|
   |                                               |
   |<<============ DATA (IPv6 packets) ===========>>|
   |                                               |
```

### Multi-Address IP Hopping Example
```
Client                                          Server (multi-homed)
   |                                               |
   |-------- PSH (knock to 10.0.0.1:4001) ------->>|
   |-------- PSH (knock to 192.168.1.1:4001) ---->>|
   |-------- PSH (knock to 10.0.0.1:4002) ------->>|
   |                    ...                        |
   |                                               |
   |-------- HSH (handshake request) ----------->>|
   |                                               |
   |<<-- HSH|ACK (IPs: 10.0.0.1/24,              --|
   |               192.168.1.1/24,                 |
   |               2001:db8::1/64)                 |
   |                                               |
   |-------- HSH|ACK (confirm) ----------------->>|
   |                                               |
   |--- DATA to 10.0.0.1:4001 ------------------>>|
   |--- DATA to 192.168.1.1:4002 --------------->>|  (IP + port hopping)
   |<<- DATA from 2001:db8::1:4003 ---------------|
   |--- DATA to 10.0.0.1:4003 ------------------>>|
   |                                               |
```
