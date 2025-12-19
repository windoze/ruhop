//! GoHop Protocol Implementation
//!
//! A UDP-based VPN protocol with port hopping capabilities.
//!
//! # Memory Pool
//!
//! For high-throughput packet processing, this crate provides a thread-local buffer pool
//! to reduce memory allocations. Use the `*_pooled` methods on [`Cipher`] and [`Packet`]
//! for best performance:
//!
//! ```rust
//! use hop_protocol::{Cipher, Packet, BufferPool};
//!
//! let cipher = Cipher::new(b"secret-key");
//! let packet = Packet::data(1, 0x1234, vec![1, 2, 3]);
//!
//! // Pooled encryption - buffer returned to pool when dropped
//! let encrypted = cipher.encrypt_pooled(&packet, 0).unwrap();
//!
//! // Or encrypt into a reusable buffer
//! let mut output = Vec::with_capacity(2048);
//! cipher.encrypt_into(&packet, 0, &mut output).unwrap();
//! ```

mod address;
mod buffer_pool;
mod crypto;
mod error;
mod flags;
mod fragment;
mod packet;
mod pool;
mod session;
pub mod transport;

pub use address::{AssignedAddress, AssignedAddresses, HandshakeResponse, IpAddress};
pub use buffer_pool::{BufferPool, PooledBuffer};
pub use crypto::Cipher;
pub use error::{Error, Result};
pub use flags::Flags;
pub use fragment::{fragment_packet, FragmentAssembler, FragmentedPacket};
pub use packet::{Packet, PacketHeader, HOP_HDR_LEN};
pub use pool::{IpPool, Ipv4Pool, Ipv6Pool};
pub use session::{Session, SessionId, SessionState};

/// Protocol version
/// Version 0x01: Original protocol with IPv4 only
/// Version 0x02: Added IPv6 support with typed address encoding
/// Version 0x03: Added multi-address support for IP hopping
/// Version 0x04: Added DNS server push in handshake response
pub const HOP_PROTO_VERSION: u8 = 0x04;

/// Default MTU
pub const DEFAULT_MTU: usize = 1400;

/// Interface buffer size
pub const IFACE_BUFSIZE: usize = 2000;
