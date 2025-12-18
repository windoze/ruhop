//! GoHop Protocol Implementation
//!
//! A UDP-based VPN protocol with port hopping capabilities.

mod address;
mod crypto;
mod error;
mod flags;
mod fragment;
mod packet;
mod pool;
mod session;
pub mod transport;

pub use address::{AssignedAddress, AssignedAddresses, HandshakeResponse, IpAddress};
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
