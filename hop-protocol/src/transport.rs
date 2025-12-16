//! Abstract transport layer for VPN implementations
//!
//! This module provides async transport traits for sending and receiving packets
//! through network interfaces. The design is TUN-compatible and interface-agnostic,
//! allowing different implementations for various TUN libraries or test mocks.
//!
//! # Architecture
//!
//! The transport layer is split into two main traits:
//! - [`TunTransport`]: For TUN interface operations (IP packets to/from the OS)
//! - [`UdpTransport`]: For UDP socket operations (encrypted packets to/from peers)
//!
//! Both traits are fully async and designed to be used with async runtimes like tokio.
//!
//! # Mock Implementations
//!
//! The [`mock`] module provides mock implementations for testing:
//! - [`mock::MockTunDevice`]: Simulates a TUN interface with packet injection and capture
//! - [`mock::MockUdpSocket`]: Simulates UDP socket operations
//! - [`mock::IpPacketBuilder`]: Helper for building test IP packets
//!
//! # Example
//!
//! ```ignore
//! use hop_protocol::transport::{TunTransport, UdpTransport};
//!
//! async fn vpn_loop<T: TunTransport, U: UdpTransport>(
//!     tun: &T,
//!     udp: &U,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let mut buf = vec![0u8; 2000];
//!
//!     // Read from TUN (IP packet from OS)
//!     let n = tun.recv(&mut buf).await?;
//!
//!     // Process and encrypt packet...
//!
//!     // Send via UDP to peer
//!     udp.send_to(&buf[..n], peer_addr).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod mock;

use async_trait::async_trait;
use std::net::SocketAddr;

use crate::error::Result;

/// Information about a TUN interface
#[derive(Debug, Clone)]
pub struct TunInfo {
    /// Interface name (e.g., "tun0", "utun3")
    pub name: String,
    /// Maximum transmission unit size
    pub mtu: u16,
}

/// Async transport trait for TUN interface operations
///
/// This trait abstracts the TUN device for sending and receiving IP packets.
/// The TUN interface operates at layer 3 (IP), meaning packets are raw IP
/// datagrams without Ethernet framing.
///
/// # Implementation Notes
///
/// - `recv` should block until data is available or the interface is closed
/// - `send` should be non-blocking if the interface buffer has space
/// - Implementations should handle MTU constraints appropriately
/// - The interface may be split into separate read/write handles for concurrent access
#[async_trait]
pub trait TunTransport: Send + Sync {
    /// Receive an IP packet from the TUN interface
    ///
    /// Reads a single IP packet from the operating system's network stack.
    /// This is traffic that the OS wants to send through the VPN tunnel.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to store the received packet. Should be at least MTU-sized.
    ///
    /// # Returns
    ///
    /// * `Ok(n)` - Number of bytes read into `buf`
    /// * `Err(e)` - If the read operation failed
    ///
    /// # Cancel Safety
    ///
    /// This method should be cancel-safe. If cancelled, no data is lost.
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;

    /// Send an IP packet to the TUN interface
    ///
    /// Writes a single IP packet to the operating system's network stack.
    /// This is decrypted traffic received from the VPN peer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The IP packet to send
    ///
    /// # Returns
    ///
    /// * `Ok(n)` - Number of bytes written
    /// * `Err(e)` - If the write operation failed
    async fn send(&self, buf: &[u8]) -> Result<usize>;

    /// Get information about the TUN interface
    fn info(&self) -> &TunInfo;

    /// Get the MTU of the interface
    fn mtu(&self) -> u16 {
        self.info().mtu
    }

    /// Get the interface name
    fn name(&self) -> &str {
        &self.info().name
    }
}

/// Async transport trait for UDP socket operations
///
/// This trait abstracts UDP socket operations for sending and receiving
/// encrypted VPN packets to/from peers. Supports the port hopping feature
/// of the GoHop protocol through flexible addressing.
///
/// # Implementation Notes
///
/// - Implementations should handle address reuse for port hopping
/// - The socket may be bound to multiple addresses for hopping
/// - Received packets include the source address for routing decisions
#[async_trait]
pub trait UdpTransport: Send + Sync {
    /// Receive a UDP datagram
    ///
    /// Reads a single UDP datagram and returns the sender's address.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to store the received datagram
    ///
    /// # Returns
    ///
    /// * `Ok((n, addr))` - Number of bytes read and sender's address
    /// * `Err(e)` - If the receive operation failed
    ///
    /// # Cancel Safety
    ///
    /// This method should be cancel-safe. If cancelled, no data is lost.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;

    /// Send a UDP datagram to the specified address
    ///
    /// # Arguments
    ///
    /// * `buf` - The datagram payload to send
    /// * `addr` - The destination address
    ///
    /// # Returns
    ///
    /// * `Ok(n)` - Number of bytes sent
    /// * `Err(e)` - If the send operation failed
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;

    /// Get the local address this transport is bound to
    fn local_addr(&self) -> Result<SocketAddr>;
}

/// Split TUN transport into separate read and write halves
///
/// This trait allows splitting a TUN transport into separate handles for
/// concurrent read and write operations. This is useful for full-duplex
/// VPN implementations where reading and writing happen in separate tasks.
pub trait TunTransportSplit: TunTransport + Sized {
    /// The read half type
    type ReadHalf: TunTransportRead;
    /// The write half type
    type WriteHalf: TunTransportWrite;

    /// Split the transport into read and write halves
    fn split(self) -> (Self::ReadHalf, Self::WriteHalf);
}

/// Read half of a split TUN transport
#[async_trait]
pub trait TunTransportRead: Send + Sync {
    /// Receive an IP packet from the TUN interface
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
}

/// Write half of a split TUN transport
#[async_trait]
pub trait TunTransportWrite: Send + Sync {
    /// Send an IP packet to the TUN interface
    async fn send(&self, buf: &[u8]) -> Result<usize>;
}

/// Split UDP transport into separate read and write halves
pub trait UdpTransportSplit: UdpTransport + Sized {
    /// The read half type
    type ReadHalf: UdpTransportRead;
    /// The write half type
    type WriteHalf: UdpTransportWrite;

    /// Split the transport into read and write halves
    fn split(self) -> (Self::ReadHalf, Self::WriteHalf);
}

/// Read half of a split UDP transport
#[async_trait]
pub trait UdpTransportRead: Send + Sync {
    /// Receive a UDP datagram
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
}

/// Write half of a split UDP transport
#[async_trait]
pub trait UdpTransportWrite: Send + Sync {
    /// Send a UDP datagram to the specified address
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;
}

/// Configuration for transport layer operations
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Buffer size for interface reads/writes
    pub buffer_size: usize,
    /// Read timeout in milliseconds (0 = no timeout)
    pub read_timeout_ms: u64,
    /// Write timeout in milliseconds (0 = no timeout)
    pub write_timeout_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            buffer_size: crate::IFACE_BUFSIZE,
            read_timeout_ms: 0,
            write_timeout_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.buffer_size, crate::IFACE_BUFSIZE);
        assert_eq!(config.read_timeout_ms, 0);
        assert_eq!(config.write_timeout_ms, 0);
    }
}
