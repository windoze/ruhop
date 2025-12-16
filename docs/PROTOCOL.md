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

- Both client and server maintain multiple UDP address mappings
- Server can advertise multiple IP addresses during handshake (multi-homed servers)
- When sending, a random address/port from the known set is selected
- Client can hop between different server IPs and ports for improved obfuscation
- This provides resilience against IP blocking and port blocking

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
