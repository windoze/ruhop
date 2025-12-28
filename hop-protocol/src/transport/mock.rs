//! Mock transport implementations for testing
//!
//! This module provides mock implementations of the transport traits that simulate
//! TUN interface behavior with full payload analysis capabilities. These mocks are
//! useful for:
//!
//! - Unit testing protocol correctness without real network interfaces
//! - Integration testing VPN data flows
//! - Analyzing packet contents for debugging
//! - Simulating various network conditions (delays, packet loss, reordering)
//!
//! # Example
//!
//! ```ignore
//! use hop_protocol::transport::mock::{MockTunDevice, PacketCapture};
//! use hop_protocol::transport::TunTransport;
//!
//! async fn example() {
//!     let device = MockTunDevice::new("tun0", 1500);
//!
//!     // Simulate OS sending an IP packet through the VPN
//!     let ip_packet = vec![0x45, 0x00, /* ... IPv4 header + payload */];
//!     device.inject_recv_packet(ip_packet);
//!
//!     // VPN code would read this packet
//!     let mut buf = vec![0u8; 2000];
//!     let n = device.recv(&mut buf).await.unwrap();
//!
//!     // Analyze what the VPN sent back to the OS
//!     let capture = device.capture();
//!     for packet in capture.sent_packets() {
//!         println!("Sent packet: {} bytes", packet.data.len());
//!     }
//! }
//! ```

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;

use super::{TunInfo, TunTransport, UdpTransport};
use crate::error::Result;
use crate::Error;

/// Analyzed information from an IP packet
#[derive(Debug, Clone)]
pub struct IpPacketInfo {
    /// IP version (4 or 6)
    pub version: u8,
    /// Source IP address
    pub src_addr: IpAddr,
    /// Destination IP address
    pub dst_addr: IpAddr,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
    pub protocol: u8,
    /// Total packet length
    pub total_length: u16,
    /// TTL (IPv4) or Hop Limit (IPv6)
    pub ttl: u8,
    /// Header length in bytes
    pub header_length: usize,
    /// Payload (data after IP header)
    pub payload: Vec<u8>,
    /// Raw packet bytes
    pub raw: Vec<u8>,
}

/// IP address enum for packet analysis
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl std::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddr::V4(addr) => write!(f, "{}", addr),
            IpAddr::V6(addr) => write!(f, "{}", addr),
        }
    }
}

impl IpPacketInfo {
    /// Parse an IP packet from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let version = (data[0] >> 4) & 0x0F;

        match version {
            4 => Self::parse_ipv4(data),
            6 => Self::parse_ipv6(data),
            _ => None,
        }
    }

    fn parse_ipv4(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize;
        let header_length = ihl * 4;

        if data.len() < header_length {
            return None;
        }

        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let protocol = data[9];
        let ttl = data[8];

        let src_addr = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        let payload = if data.len() > header_length {
            data[header_length..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            version: 4,
            src_addr,
            dst_addr,
            protocol,
            total_length,
            ttl,
            header_length,
            payload,
            raw: data.to_vec(),
        })
    }

    fn parse_ipv6(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6]; // Protocol
        let hop_limit = data[7];

        let mut src_bytes = [0u8; 16];
        let mut dst_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&data[8..24]);
        dst_bytes.copy_from_slice(&data[24..40]);

        let src_addr = IpAddr::V6(Ipv6Addr::from(src_bytes));
        let dst_addr = IpAddr::V6(Ipv6Addr::from(dst_bytes));

        let payload = if data.len() > 40 {
            data[40..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            version: 6,
            src_addr,
            dst_addr,
            protocol: next_header,
            total_length: 40 + payload_length,
            ttl: hop_limit,
            header_length: 40,
            payload,
            raw: data.to_vec(),
        })
    }

    /// Check if this is a TCP packet
    pub fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    /// Check if this is a UDP packet
    pub fn is_udp(&self) -> bool {
        self.protocol == 17
    }

    /// Check if this is an ICMP packet
    pub fn is_icmp(&self) -> bool {
        self.protocol == 1 || self.protocol == 58 // ICMPv4 or ICMPv6
    }

    /// Get protocol name
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            58 => "ICMPv6",
            _ => "Unknown",
        }
    }

    /// Parse UDP header if this is a UDP packet
    pub fn parse_udp(&self) -> Option<UdpInfo> {
        if !self.is_udp() || self.payload.len() < 8 {
            return None;
        }

        let src_port = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        let dst_port = u16::from_be_bytes([self.payload[2], self.payload[3]]);
        let length = u16::from_be_bytes([self.payload[4], self.payload[5]]);
        let checksum = u16::from_be_bytes([self.payload[6], self.payload[7]]);

        let data = if self.payload.len() > 8 {
            self.payload[8..].to_vec()
        } else {
            Vec::new()
        };

        Some(UdpInfo {
            src_port,
            dst_port,
            length,
            checksum,
            data,
        })
    }

    /// Parse TCP header if this is a TCP packet
    pub fn parse_tcp(&self) -> Option<TcpInfo> {
        if !self.is_tcp() || self.payload.len() < 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        let dst_port = u16::from_be_bytes([self.payload[2], self.payload[3]]);
        let seq_num = u32::from_be_bytes([
            self.payload[4],
            self.payload[5],
            self.payload[6],
            self.payload[7],
        ]);
        let ack_num = u32::from_be_bytes([
            self.payload[8],
            self.payload[9],
            self.payload[10],
            self.payload[11],
        ]);

        let data_offset = ((self.payload[12] >> 4) & 0x0F) as usize * 4;
        let flags = self.payload[13];

        let data = if self.payload.len() > data_offset {
            self.payload[data_offset..].to_vec()
        } else {
            Vec::new()
        };

        Some(TcpInfo {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            flags,
            data,
        })
    }
}

/// UDP header information
#[derive(Debug, Clone)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub data: Vec<u8>,
}

/// TCP header information
#[derive(Debug, Clone)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags: u8,
    pub data: Vec<u8>,
}

impl TcpInfo {
    pub fn is_syn(&self) -> bool {
        self.flags & 0x02 != 0
    }
    pub fn is_ack(&self) -> bool {
        self.flags & 0x10 != 0
    }
    pub fn is_fin(&self) -> bool {
        self.flags & 0x01 != 0
    }
    pub fn is_rst(&self) -> bool {
        self.flags & 0x04 != 0
    }
    pub fn is_psh(&self) -> bool {
        self.flags & 0x08 != 0
    }
}

/// Packet capture and analysis for mock devices
#[derive(Debug, Default)]
pub struct PacketCapture {
    /// Packets sent to the TUN device (from VPN to OS)
    sent: Vec<CapturedPacket>,
    /// Packets received from the TUN device (from OS to VPN)
    received: Vec<CapturedPacket>,
}

/// A captured packet with metadata
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// Raw packet bytes
    pub data: Vec<u8>,
    /// Timestamp when captured (monotonic counter)
    pub timestamp: u64,
    /// Parsed IP packet info (if valid IP packet)
    pub ip_info: Option<IpPacketInfo>,
}

impl PacketCapture {
    /// Get all packets sent to the TUN device
    pub fn sent_packets(&self) -> &[CapturedPacket] {
        &self.sent
    }

    /// Get all packets received from the TUN device
    pub fn received_packets(&self) -> &[CapturedPacket] {
        &self.received
    }

    /// Get raw bytes of all sent packets
    pub fn sent_bytes(&self) -> Vec<&[u8]> {
        self.sent.iter().map(|p| p.data.as_slice()).collect()
    }

    /// Get raw bytes of all received packets
    pub fn received_bytes(&self) -> Vec<&[u8]> {
        self.received.iter().map(|p| p.data.as_slice()).collect()
    }

    /// Count sent packets
    pub fn sent_count(&self) -> usize {
        self.sent.len()
    }

    /// Count received packets
    pub fn received_count(&self) -> usize {
        self.received.len()
    }

    /// Total bytes sent
    pub fn total_sent_bytes(&self) -> usize {
        self.sent.iter().map(|p| p.data.len()).sum()
    }

    /// Total bytes received
    pub fn total_received_bytes(&self) -> usize {
        self.received.iter().map(|p| p.data.len()).sum()
    }

    /// Filter sent packets by protocol
    pub fn sent_by_protocol(&self, protocol: u8) -> Vec<&CapturedPacket> {
        self.sent
            .iter()
            .filter(|p| {
                p.ip_info
                    .as_ref()
                    .is_some_and(|info| info.protocol == protocol)
            })
            .collect()
    }

    /// Get all sent TCP packets
    pub fn sent_tcp(&self) -> Vec<&CapturedPacket> {
        self.sent_by_protocol(6)
    }

    /// Get all sent UDP packets
    pub fn sent_udp(&self) -> Vec<&CapturedPacket> {
        self.sent_by_protocol(17)
    }

    /// Clear all captured packets
    pub fn clear(&mut self) {
        self.sent.clear();
        self.received.clear();
    }
}

/// Mock TUN device for testing
///
/// Simulates a TUN interface with packet capture and injection capabilities.
/// This is the primary mock for testing VPN protocol correctness.
#[allow(clippy::type_complexity)]
pub struct MockTunDevice {
    info: TunInfo,
    /// Queue of packets to be received (injected by test)
    recv_queue: Mutex<VecDeque<Vec<u8>>>,
    /// Captured packet data
    capture: RwLock<PacketCapture>,
    /// Monotonic timestamp counter
    timestamp: AtomicU64,
    /// Whether the device is "up" (active)
    is_up: RwLock<bool>,
    /// Optional callback for sent packets
    on_send: Mutex<Option<Box<dyn Fn(&[u8]) + Send + Sync>>>,
}

impl MockTunDevice {
    /// Create a new mock TUN device
    pub fn new(name: &str, mtu: u16) -> Self {
        Self {
            info: TunInfo {
                name: name.to_string(),
                mtu,
            },
            recv_queue: Mutex::new(VecDeque::new()),
            capture: RwLock::new(PacketCapture::default()),
            timestamp: AtomicU64::new(0),
            is_up: RwLock::new(true),
            on_send: Mutex::new(None),
        }
    }

    /// Create with standard VPN MTU (1400)
    pub fn with_default_mtu(name: &str) -> Self {
        Self::new(name, crate::DEFAULT_MTU as u16)
    }

    /// Inject a packet to be received by the VPN (simulates OS sending packet)
    pub fn inject_recv_packet(&self, data: Vec<u8>) {
        let ts = self.timestamp.fetch_add(1, Ordering::SeqCst);
        let ip_info = IpPacketInfo::parse(&data);

        let mut capture = self.capture.write().unwrap();
        capture.received.push(CapturedPacket {
            data: data.clone(),
            timestamp: ts,
            ip_info,
        });

        self.recv_queue.lock().unwrap().push_back(data);
    }

    /// Inject multiple packets
    pub fn inject_recv_packets(&self, packets: Vec<Vec<u8>>) {
        for packet in packets {
            self.inject_recv_packet(packet);
        }
    }

    /// Get packet capture data
    pub fn capture(&self) -> PacketCapture {
        self.capture.read().unwrap().clone()
    }

    /// Get mutable reference to capture (for clearing, etc.)
    pub fn capture_mut(&self) -> std::sync::RwLockWriteGuard<'_, PacketCapture> {
        self.capture.write().unwrap()
    }

    /// Check if there are packets waiting to be received
    pub fn has_pending_recv(&self) -> bool {
        !self.recv_queue.lock().unwrap().is_empty()
    }

    /// Get count of pending recv packets
    pub fn pending_recv_count(&self) -> usize {
        self.recv_queue.lock().unwrap().len()
    }

    /// Set the device up/down state
    pub fn set_up(&self, up: bool) {
        *self.is_up.write().unwrap() = up;
    }

    /// Check if device is up
    pub fn is_up(&self) -> bool {
        *self.is_up.read().unwrap()
    }

    /// Set a callback to be invoked when packets are sent
    pub fn on_send<F>(&self, callback: F)
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        *self.on_send.lock().unwrap() = Some(Box::new(callback));
    }

    /// Clear the send callback
    pub fn clear_on_send(&self) {
        *self.on_send.lock().unwrap() = None;
    }

    /// Create a pair of connected mock devices (for client-server testing)
    pub fn create_pair(mtu: u16) -> (Arc<Self>, Arc<Self>) {
        let client = Arc::new(Self::new("tun-client", mtu));
        let server = Arc::new(Self::new("tun-server", mtu));

        // Connect them: packets sent to one appear in the other's recv queue
        let server_clone = server.clone();
        client.on_send(move |data| {
            server_clone.inject_recv_packet(data.to_vec());
        });

        let client_clone = client.clone();
        server.on_send(move |data| {
            client_clone.inject_recv_packet(data.to_vec());
        });

        (client, server)
    }
}

impl Clone for PacketCapture {
    fn clone(&self) -> Self {
        Self {
            sent: self.sent.clone(),
            received: self.received.clone(),
        }
    }
}

#[async_trait]
impl TunTransport for MockTunDevice {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.is_up() {
            return Err(Error::Transport("device is down".into()));
        }

        let packet = self
            .recv_queue
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| Error::Transport("no packets available".into()))?;

        let len = packet.len().min(buf.len());
        buf[..len].copy_from_slice(&packet[..len]);
        Ok(len)
    }

    async fn send(&self, buf: &[u8]) -> Result<usize> {
        if !self.is_up() {
            return Err(Error::Transport("device is down".into()));
        }

        if buf.len() > self.info.mtu as usize {
            return Err(Error::Transport(format!(
                "packet size {} exceeds MTU {}",
                buf.len(),
                self.info.mtu
            )));
        }

        let ts = self.timestamp.fetch_add(1, Ordering::SeqCst);
        let ip_info = IpPacketInfo::parse(buf);

        let mut capture = self.capture.write().unwrap();
        capture.sent.push(CapturedPacket {
            data: buf.to_vec(),
            timestamp: ts,
            ip_info,
        });

        // Invoke callback if set
        if let Some(ref callback) = *self.on_send.lock().unwrap() {
            callback(buf);
        }

        Ok(buf.len())
    }

    fn info(&self) -> &TunInfo {
        &self.info
    }
}

/// Mock UDP transport for testing
///
/// Simulates UDP socket operations with packet capture capabilities.
pub struct MockUdpSocket {
    local_addr: SocketAddr,
    /// Queue of (data, from_addr) to be received
    recv_queue: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// Sent packets: (data, to_addr)
    sent_packets: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    /// Connected sockets for simulation
    connected: Mutex<Option<Arc<MockUdpSocket>>>,
}

impl MockUdpSocket {
    /// Create a new mock UDP socket
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            recv_queue: Mutex::new(VecDeque::new()),
            sent_packets: Mutex::new(Vec::new()),
            connected: Mutex::new(None),
        }
    }

    /// Create with an auto-assigned address
    pub fn bind_any() -> Self {
        use rand::Rng;
        let port: u16 = rand::thread_rng().gen_range(10000..60000);
        Self::new(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    /// Inject a packet to be received
    pub fn inject_recv(&self, data: Vec<u8>, from: SocketAddr) {
        self.recv_queue.lock().unwrap().push_back((data, from));
    }

    /// Get all sent packets
    pub fn get_sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        self.sent_packets.lock().unwrap().clone()
    }

    /// Check if there are pending packets
    pub fn has_pending(&self) -> bool {
        !self.recv_queue.lock().unwrap().is_empty()
    }

    /// Connect two mock sockets (bidirectional)
    pub fn connect_pair(a: &Arc<Self>, b: &Arc<Self>) {
        *a.connected.lock().unwrap() = Some(b.clone());
        *b.connected.lock().unwrap() = Some(a.clone());
    }
}

#[async_trait]
impl UdpTransport for MockUdpSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (data, from) = self
            .recv_queue
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| Error::Transport("no packets available".into()))?;

        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok((len, from))
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        self.sent_packets.lock().unwrap().push((buf.to_vec(), addr));

        // If connected to another socket, inject into its recv queue
        if let Some(ref peer) = *self.connected.lock().unwrap() {
            peer.inject_recv(buf.to_vec(), self.local_addr);
        }

        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// Builder for creating test IP packets
pub struct IpPacketBuilder {
    version: u8,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    ttl: u8,
    payload: Vec<u8>,
}

impl IpPacketBuilder {
    /// Create an IPv4 packet builder
    pub fn ipv4() -> Self {
        Self {
            version: 4,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            protocol: 6, // TCP
            ttl: 64,
            payload: Vec::new(),
        }
    }

    /// Create an IPv6 packet builder
    pub fn ipv6() -> Self {
        Self {
            version: 6,
            src: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            dst: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            protocol: 6, // TCP
            ttl: 64,
            payload: Vec::new(),
        }
    }

    /// Set source address
    pub fn src(mut self, addr: IpAddr) -> Self {
        self.src = addr;
        self
    }

    /// Set source IPv4 address
    pub fn src_v4(self, a: u8, b: u8, c: u8, d: u8) -> Self {
        self.src(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    /// Set destination address
    pub fn dst(mut self, addr: IpAddr) -> Self {
        self.dst = addr;
        self
    }

    /// Set destination IPv4 address
    pub fn dst_v4(self, a: u8, b: u8, c: u8, d: u8) -> Self {
        self.dst(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    /// Set protocol (6=TCP, 17=UDP, 1=ICMP)
    pub fn protocol(mut self, proto: u8) -> Self {
        self.protocol = proto;
        self
    }

    /// Set as TCP packet
    pub fn tcp(self) -> Self {
        self.protocol(6)
    }

    /// Set as UDP packet
    pub fn udp(self) -> Self {
        self.protocol(17)
    }

    /// Set as ICMP packet
    pub fn icmp(self) -> Self {
        self.protocol(1)
    }

    /// Set TTL/hop limit
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set payload data
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Add a UDP header with the given ports and data
    pub fn with_udp(self, src_port: u16, dst_port: u16, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(8 + data.len());
        payload.extend_from_slice(&src_port.to_be_bytes());
        payload.extend_from_slice(&dst_port.to_be_bytes());
        let length = (8 + data.len()) as u16;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(&[0, 0]); // Checksum (0 for simplicity)
        payload.extend_from_slice(data);
        self.udp().payload(payload)
    }

    /// Add a TCP header with the given parameters
    pub fn with_tcp(
        self,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        data: &[u8],
    ) -> Self {
        let mut payload = Vec::with_capacity(20 + data.len());
        payload.extend_from_slice(&src_port.to_be_bytes());
        payload.extend_from_slice(&dst_port.to_be_bytes());
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(&ack.to_be_bytes());
        payload.push(0x50); // Data offset (5 * 4 = 20 bytes)
        payload.push(flags);
        payload.extend_from_slice(&[0xFF, 0xFF]); // Window size
        payload.extend_from_slice(&[0, 0]); // Checksum
        payload.extend_from_slice(&[0, 0]); // Urgent pointer
        payload.extend_from_slice(data);
        self.tcp().payload(payload)
    }

    /// Build the IP packet
    pub fn build(self) -> Vec<u8> {
        match self.version {
            4 => self.build_ipv4(),
            6 => self.build_ipv6(),
            _ => panic!("Invalid IP version"),
        }
    }

    fn build_ipv4(self) -> Vec<u8> {
        let IpAddr::V4(src) = self.src else {
            panic!("Source address must be IPv4");
        };
        let IpAddr::V4(dst) = self.dst else {
            panic!("Destination address must be IPv4");
        };

        let total_length = 20 + self.payload.len();
        let mut packet = Vec::with_capacity(total_length);

        // Version (4) + IHL (5) = 0x45
        packet.push(0x45);
        // DSCP + ECN
        packet.push(0x00);
        // Total length
        packet.extend_from_slice(&(total_length as u16).to_be_bytes());
        // Identification
        packet.extend_from_slice(&[0x00, 0x00]);
        // Flags + Fragment offset
        packet.extend_from_slice(&[0x40, 0x00]); // Don't fragment
                                                 // TTL
        packet.push(self.ttl);
        // Protocol
        packet.push(self.protocol);
        // Header checksum (0 for simplicity, real impl would calculate)
        packet.extend_from_slice(&[0x00, 0x00]);
        // Source address
        packet.extend_from_slice(&src.octets());
        // Destination address
        packet.extend_from_slice(&dst.octets());
        // Payload
        packet.extend_from_slice(&self.payload);

        packet
    }

    fn build_ipv6(self) -> Vec<u8> {
        let IpAddr::V6(src) = self.src else {
            panic!("Source address must be IPv6");
        };
        let IpAddr::V6(dst) = self.dst else {
            panic!("Destination address must be IPv6");
        };

        let mut packet = Vec::with_capacity(40 + self.payload.len());

        // Version (6) + Traffic Class + Flow Label
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        // Payload length
        packet.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        // Next header (protocol)
        packet.push(self.protocol);
        // Hop limit
        packet.push(self.ttl);
        // Source address
        packet.extend_from_slice(&src.octets());
        // Destination address
        packet.extend_from_slice(&dst.octets());
        // Payload
        packet.extend_from_slice(&self.payload);

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_packet_builder_ipv4() {
        let packet = IpPacketBuilder::ipv4()
            .src_v4(192, 168, 1, 1)
            .dst_v4(192, 168, 1, 2)
            .tcp()
            .ttl(128)
            .payload(vec![1, 2, 3, 4])
            .build();

        let info = IpPacketInfo::parse(&packet).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.src_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(info.dst_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        assert!(info.is_tcp());
        assert_eq!(info.ttl, 128);
        assert_eq!(info.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_ip_packet_builder_ipv6() {
        let packet = IpPacketBuilder::ipv6()
            .udp()
            .payload(vec![5, 6, 7, 8])
            .build();

        let info = IpPacketInfo::parse(&packet).unwrap();
        assert_eq!(info.version, 6);
        assert!(info.is_udp());
        assert_eq!(info.payload, vec![5, 6, 7, 8]);
    }

    #[test]
    fn test_ip_packet_builder_with_udp() {
        let packet = IpPacketBuilder::ipv4()
            .src_v4(10, 0, 0, 1)
            .dst_v4(10, 0, 0, 2)
            .with_udp(12345, 53, b"DNS query")
            .build();

        let info = IpPacketInfo::parse(&packet).unwrap();
        assert!(info.is_udp());

        let udp = info.parse_udp().unwrap();
        assert_eq!(udp.src_port, 12345);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(udp.data, b"DNS query");
    }

    #[test]
    fn test_ip_packet_builder_with_tcp() {
        let packet = IpPacketBuilder::ipv4()
            .src_v4(10, 0, 0, 1)
            .dst_v4(10, 0, 0, 2)
            .with_tcp(54321, 80, 1000, 0, 0x02, b"") // SYN
            .build();

        let info = IpPacketInfo::parse(&packet).unwrap();
        assert!(info.is_tcp());

        let tcp = info.parse_tcp().unwrap();
        assert_eq!(tcp.src_port, 54321);
        assert_eq!(tcp.dst_port, 80);
        assert_eq!(tcp.seq_num, 1000);
        assert!(tcp.is_syn());
        assert!(!tcp.is_ack());
    }

    #[tokio::test]
    async fn test_mock_tun_device() {
        let device = MockTunDevice::new("tun0", 1500);

        // Test device info
        assert_eq!(device.name(), "tun0");
        assert_eq!(device.mtu(), 1500);
        assert!(device.is_up());

        // Inject a packet
        let test_packet = IpPacketBuilder::ipv4()
            .src_v4(10, 0, 0, 1)
            .dst_v4(8, 8, 8, 8)
            .with_udp(12345, 53, b"test")
            .build();

        device.inject_recv_packet(test_packet.clone());
        assert!(device.has_pending_recv());
        assert_eq!(device.pending_recv_count(), 1);

        // Receive the packet
        let mut buf = vec![0u8; 2000];
        let n = device.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &test_packet[..]);
        assert!(!device.has_pending_recv());

        // Capture should show the received packet
        let capture = device.capture();
        assert_eq!(capture.received_count(), 1);
        let recv_pkt = &capture.received_packets()[0];
        let ip_info = recv_pkt.ip_info.as_ref().unwrap();
        assert!(ip_info.is_udp());

        // Send a packet
        let response = IpPacketBuilder::ipv4()
            .src_v4(8, 8, 8, 8)
            .dst_v4(10, 0, 0, 1)
            .with_udp(53, 12345, b"response")
            .build();

        let n = device.send(&response).await.unwrap();
        assert_eq!(n, response.len());

        // Capture should show the sent packet
        let capture = device.capture();
        assert_eq!(capture.sent_count(), 1);
        let sent_pkt = &capture.sent_packets()[0];
        assert_eq!(sent_pkt.data, response);
    }

    #[tokio::test]
    async fn test_mock_tun_device_down() {
        let device = MockTunDevice::new("tun0", 1500);
        device.set_up(false);

        let mut buf = vec![0u8; 100];
        assert!(device.recv(&mut buf).await.is_err());
        assert!(device.send(&[1, 2, 3]).await.is_err());
    }

    #[tokio::test]
    async fn test_mock_tun_device_mtu_enforcement() {
        let device = MockTunDevice::new("tun0", 100);

        // Packet larger than MTU should fail
        let large_packet = vec![0u8; 200];
        assert!(device.send(&large_packet).await.is_err());

        // Packet within MTU should succeed
        let small_packet = vec![0u8; 50];
        assert!(device.send(&small_packet).await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_tun_device_pair() {
        let (client, server) = MockTunDevice::create_pair(1500);

        // Client sends a packet
        let packet = IpPacketBuilder::ipv4()
            .src_v4(10, 0, 0, 1)
            .dst_v4(10, 0, 0, 2)
            .with_tcp(1234, 80, 100, 0, 0x02, b"SYN")
            .build();

        client.send(&packet).await.unwrap();

        // Server should receive it
        assert!(server.has_pending_recv());
        let mut buf = vec![0u8; 2000];
        let n = server.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &packet[..]);

        // Server responds
        let response = IpPacketBuilder::ipv4()
            .src_v4(10, 0, 0, 2)
            .dst_v4(10, 0, 0, 1)
            .with_tcp(80, 1234, 200, 101, 0x12, b"SYN-ACK")
            .build();

        server.send(&response).await.unwrap();

        // Client should receive it
        assert!(client.has_pending_recv());
        let n = client.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &response[..]);
    }

    #[tokio::test]
    async fn test_mock_udp_socket() {
        let socket = MockUdpSocket::new("127.0.0.1:5000".parse().unwrap());

        // Test local addr
        assert_eq!(
            socket.local_addr().unwrap(),
            "127.0.0.1:5000".parse().unwrap()
        );

        // Inject and receive
        let from: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        socket.inject_recv(vec![1, 2, 3], from);

        let mut buf = vec![0u8; 100];
        let (n, addr) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(addr, from);
        assert_eq!(&buf[..n], &[1, 2, 3]);

        // Send and check
        let to: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        socket.send_to(&[4, 5, 6], to).await.unwrap();

        let sent = socket.get_sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, vec![4, 5, 6]);
        assert_eq!(sent[0].1, to);
    }

    #[tokio::test]
    async fn test_mock_udp_socket_pair() {
        let client = Arc::new(MockUdpSocket::new("127.0.0.1:5000".parse().unwrap()));
        let server = Arc::new(MockUdpSocket::new("127.0.0.1:6000".parse().unwrap()));

        MockUdpSocket::connect_pair(&client, &server);

        // Client sends to server
        let server_addr = server.local_addr().unwrap();
        client.send_to(b"hello", server_addr).await.unwrap();

        // Server should receive
        assert!(server.has_pending());
        let mut buf = vec![0u8; 100];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, client.local_addr().unwrap());

        // Server sends back
        let client_addr = client.local_addr().unwrap();
        server.send_to(b"world", client_addr).await.unwrap();

        // Client should receive
        assert!(client.has_pending());
        let (n, from) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
        assert_eq!(from, server.local_addr().unwrap());
    }

    #[test]
    fn test_packet_capture_analysis() {
        let mut capture = PacketCapture::default();

        // Add some packets
        let tcp_packet = IpPacketBuilder::ipv4()
            .with_tcp(1234, 80, 100, 0, 0x02, b"data")
            .build();

        let udp_packet = IpPacketBuilder::ipv4().with_udp(5000, 53, b"query").build();

        capture.sent.push(CapturedPacket {
            data: tcp_packet.clone(),
            timestamp: 0,
            ip_info: IpPacketInfo::parse(&tcp_packet),
        });

        capture.sent.push(CapturedPacket {
            data: udp_packet.clone(),
            timestamp: 1,
            ip_info: IpPacketInfo::parse(&udp_packet),
        });

        assert_eq!(capture.sent_count(), 2);
        assert_eq!(capture.sent_tcp().len(), 1);
        assert_eq!(capture.sent_udp().len(), 1);
    }
}
