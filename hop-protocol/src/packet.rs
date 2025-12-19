//! Packet structure and serialization

use crate::buffer_pool::{BufferPool, PooledBuffer};
use crate::{Error, Flags, Result};

/// Header length in bytes
pub const HOP_HDR_LEN: usize = 16;

/// Packet header structure
///
/// ```text
/// +--------+--------+--------+--------+--------+--------+--------+--------+
/// | Byte 0 | Byte 1 | Byte 2 | Byte 3 | Byte 4 | Byte 5 | Byte 6 | Byte 7 |
/// +--------+--------+--------+--------+--------+--------+--------+--------+
/// |  Flag  |              Seq (uint32, big-endian)       |  Plen (uint16) |
/// +--------+--------+--------+--------+--------+--------+--------+--------+
///
/// +--------+--------+--------+--------+--------+--------+--------+--------+
/// | Byte 8 | Byte 9 | Byte10 | Byte11 | Byte12 | Byte13 | Byte14 | Byte15 |
/// +--------+--------+--------+--------+--------+--------+--------+--------+
/// |   FragPrefix    |  Frag  |         Sid (uint32)      |  Dlen (uint16) |
/// +--------+--------+--------+--------+--------+--------+--------+--------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Packet type flags
    pub flag: Flags,
    /// Sequence number
    pub seq: u32,
    /// Total payload length (for fragmentation)
    pub plen: u16,
    /// Fragment offset in original payload
    pub frag_prefix: u16,
    /// Fragment index
    pub frag: u8,
    /// Session ID
    pub sid: u32,
    /// Actual data length in this packet
    pub dlen: u16,
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            flag: Flags::data(),
            seq: 0,
            plen: 0,
            frag_prefix: 0,
            frag: 0,
            sid: 0,
            dlen: 0,
        }
    }
}

impl PacketHeader {
    /// Create a new packet header
    pub fn new(flag: Flags, seq: u32, sid: u32) -> Self {
        Self {
            flag,
            seq,
            sid,
            ..Default::default()
        }
    }

    /// Create a data packet header
    pub fn data(seq: u32, sid: u32, data_len: u16) -> Self {
        Self {
            flag: Flags::data(),
            seq,
            sid,
            plen: data_len,
            dlen: data_len,
            ..Default::default()
        }
    }

    /// Create a knock/heartbeat packet header
    pub fn push(sid: u32) -> Self {
        Self {
            flag: Flags::push(),
            sid,
            ..Default::default()
        }
    }

    /// Create a heartbeat ack packet header
    pub fn push_ack(sid: u32) -> Self {
        Self {
            flag: Flags::push().with_ack(),
            sid,
            ..Default::default()
        }
    }

    /// Create a handshake request header
    pub fn handshake(sid: u32) -> Self {
        Self {
            flag: Flags::handshake(),
            sid,
            ..Default::default()
        }
    }

    /// Create a handshake ack header
    pub fn handshake_ack(sid: u32) -> Self {
        Self {
            flag: Flags::handshake().with_ack(),
            sid,
            ..Default::default()
        }
    }

    /// Create a handshake error header
    pub fn handshake_error(sid: u32) -> Self {
        Self {
            flag: Flags::handshake().with_finish(),
            sid,
            ..Default::default()
        }
    }

    /// Create a finish request header
    pub fn finish(sid: u32) -> Self {
        Self {
            flag: Flags::finish(),
            sid,
            ..Default::default()
        }
    }

    /// Create a finish ack header
    pub fn finish_ack(sid: u32) -> Self {
        Self {
            flag: Flags::finish().with_ack(),
            sid,
            ..Default::default()
        }
    }

    /// Encode header to bytes
    pub fn encode(&self) -> [u8; HOP_HDR_LEN] {
        let mut buf = [0u8; HOP_HDR_LEN];

        buf[0] = self.flag.as_u8();

        // Seq (bytes 1-4, big-endian) - note: only using bytes 1-4 for u32
        buf[1..5].copy_from_slice(&self.seq.to_be_bytes());

        // Plen (bytes 5-6, big-endian) - but protocol shows bytes 6-7
        // Looking at protocol: Seq is bytes 1-4, Plen is bytes 5-6 (indices 5,6)
        // Wait, the diagram shows Seq at bytes 1-4 (4 bytes) then Plen at bytes 5-6 (but that's only indices 5,6)
        // Re-reading: Byte 0=Flag, Bytes 1-4=Seq(uint32), remaining of first row is Plen
        // First row: Byte 0-7, Flag=0, Seq=1-4, Plen=5-6 (indices 5,6 but diagram says 6,7)
        // The diagram labels are confusing - let me follow the field sizes:
        // Flag: 1 byte (index 0)
        // Seq: 4 bytes (indices 1-4)
        // Plen: 2 bytes (indices 5-6)
        // FragPrefix: 2 bytes (indices 7-8) - wait that's wrong too
        // Actually re-reading the byte layout more carefully:
        // Row 1 (bytes 0-7): Flag(1) + Seq(4) + Plen(2) = 7 bytes - but that's bytes 0-6
        // The diagram shows Plen at positions 6-7... let me recalculate
        // If Seq is uint32 starting at byte 1, it occupies bytes 1,2,3,4
        // Then Plen (uint16) would be at bytes 5,6
        // But diagram header says bytes 6,7 for Plen... this is confusing

        // Let me just follow the table which says:
        // Flag: 1 byte, Seq: 4 bytes, Plen: 2 bytes, FragPrefix: 2 bytes, Frag: 1 byte, Sid: 4 bytes, Dlen: 2 bytes
        // Total: 1+4+2+2+1+4+2 = 16 bytes ✓

        // So layout is:
        // [0]: Flag
        // [1-4]: Seq (4 bytes)
        // [5-6]: Plen (2 bytes)
        // [7-8]: FragPrefix (2 bytes)
        // [9]: Frag (1 byte)
        // [10-13]: Sid (4 bytes)
        // [14-15]: Dlen (2 bytes)

        buf[5..7].copy_from_slice(&self.plen.to_be_bytes());
        buf[7..9].copy_from_slice(&self.frag_prefix.to_be_bytes());
        buf[9] = self.frag;
        buf[10..14].copy_from_slice(&self.sid.to_be_bytes());
        buf[14..16].copy_from_slice(&self.dlen.to_be_bytes());

        buf
    }

    /// Decode header from bytes
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HOP_HDR_LEN {
            return Err(Error::PacketTooShort {
                expected: HOP_HDR_LEN,
                actual: buf.len(),
            });
        }

        Ok(Self {
            flag: Flags::new(buf[0]),
            seq: u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            plen: u16::from_be_bytes([buf[5], buf[6]]),
            frag_prefix: u16::from_be_bytes([buf[7], buf[8]]),
            frag: buf[9],
            sid: u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]),
            dlen: u16::from_be_bytes([buf[14], buf[15]]),
        })
    }
}

/// Complete packet with header and payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Packet header
    pub header: PacketHeader,
    /// Packet payload (actual data, not including noise)
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create a new packet
    /// Automatically sets dlen and plen in header based on payload length
    pub fn new(mut header: PacketHeader, payload: Vec<u8>) -> Self {
        let len = payload.len() as u16;
        header.dlen = len;
        if header.plen == 0 {
            header.plen = len;
        }
        Self { header, payload }
    }

    /// Create a data packet
    pub fn data(seq: u32, sid: u32, payload: Vec<u8>) -> Self {
        let dlen = payload.len() as u16;
        Self::new(PacketHeader::data(seq, sid, dlen), payload)
    }

    /// Create a knock packet (client -> server during port knocking)
    pub fn knock(sid: u32) -> Self {
        Self::new(PacketHeader::push(sid), sid.to_be_bytes().to_vec())
    }

    /// Create a heartbeat request packet
    pub fn heartbeat_request(sid: u32) -> Self {
        Self::new(PacketHeader::push(sid), Vec::new())
    }

    /// Create a heartbeat response packet
    pub fn heartbeat_response(sid: u32) -> Self {
        Self::new(PacketHeader::push_ack(sid), sid.to_be_bytes().to_vec())
    }

    /// Create a handshake request packet
    pub fn handshake_request(sid: u32) -> Self {
        Self::new(PacketHeader::handshake(sid), sid.to_be_bytes().to_vec())
    }

    /// Create a handshake response packet (server -> client) with IPv4 address
    /// Legacy method for backwards compatibility
    pub fn handshake_response(sid: u32, ip: [u8; 4], mask: u8) -> Self {
        Self::handshake_response_with_ip(sid, crate::IpAddress::from_ipv4_bytes(ip), mask)
    }

    /// Create a handshake response packet (server -> client) with any IP address
    /// Wire format v2: [version: 1] [ip_type: 1] [ip: 4 or 16] [mask: 1]
    /// Note: For multi-address support, use handshake_response_multi_ip instead
    pub fn handshake_response_with_ip(sid: u32, ip: crate::IpAddress, mask: u8) -> Self {
        Self::handshake_response_multi_ip(sid, crate::AssignedAddresses::single(ip, mask))
    }

    /// Create a handshake response packet with multiple IP addresses (for IP hopping)
    /// Wire format v3: [version: 1] [count: 1] [addr1] [addr2] ...
    /// Each addr: [ip_type: 1] [ip: 4 or 16] [mask: 1]
    pub fn handshake_response_multi_ip(sid: u32, addresses: crate::AssignedAddresses) -> Self {
        let addrs_encoded = addresses.encode();
        let mut payload = Vec::with_capacity(1 + addrs_encoded.len());
        payload.push(crate::HOP_PROTO_VERSION);
        payload.extend_from_slice(&addrs_encoded);
        Self::new(PacketHeader::handshake_ack(sid), payload)
    }

    /// Create a handshake response packet with addresses and DNS servers (v4 protocol)
    /// Wire format v4: [version: 1] [addr_count: 1] [addrs...] [dns_count: 1] [dns_ips...]
    pub fn handshake_response_v4(
        sid: u32,
        addresses: crate::AssignedAddresses,
        dns_servers: Vec<crate::IpAddress>,
    ) -> Self {
        let response = crate::HandshakeResponse::with_dns(addresses, dns_servers);
        let response_encoded = response.encode();
        let mut payload = Vec::with_capacity(1 + response_encoded.len());
        payload.push(crate::HOP_PROTO_VERSION);
        payload.extend_from_slice(&response_encoded);
        Self::new(PacketHeader::handshake_ack(sid), payload)
    }

    /// Create a handshake confirmation packet (client -> server)
    pub fn handshake_confirm(sid: u32) -> Self {
        Self::new(PacketHeader::handshake_ack(sid), sid.to_be_bytes().to_vec())
    }

    /// Create a handshake error packet
    pub fn handshake_error(sid: u32, message: &str) -> Self {
        Self::new(PacketHeader::handshake_error(sid), message.as_bytes().to_vec())
    }

    /// Create a finish request packet
    pub fn finish_request(sid: u32) -> Self {
        Self::new(PacketHeader::finish(sid), sid.to_be_bytes().to_vec())
    }

    /// Create a finish ack packet
    pub fn finish_ack(sid: u32) -> Self {
        Self::new(PacketHeader::finish_ack(sid), Vec::new())
    }

    /// Encode packet to bytes (without encryption)
    /// Returns header + payload, without noise
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HOP_HDR_LEN + self.payload.len());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Encode packet with noise bytes for traffic analysis resistance
    pub fn encode_with_noise(&self, max_noise: usize) -> Vec<u8> {
        use rand::Rng;

        let mut buf = self.encode();

        if max_noise > 0 {
            let noise_len = rand::thread_rng().gen_range(0..=max_noise);
            let noise: Vec<u8> = (0..noise_len).map(|_| rand::random()).collect();
            buf.extend_from_slice(&noise);
        }

        buf
    }

    /// Decode packet from bytes (after decryption)
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let header = PacketHeader::decode(buf)?;

        let payload_start = HOP_HDR_LEN;
        let payload_end = payload_start + header.dlen as usize;

        if buf.len() < payload_end {
            return Err(Error::PacketTooShort {
                expected: payload_end,
                actual: buf.len(),
            });
        }

        // Only take dlen bytes as payload, rest is noise
        let payload = buf[payload_start..payload_end].to_vec();

        Ok(Self { header, payload })
    }

    // ========================================================================
    // Pooled buffer methods for reduced allocations
    // ========================================================================

    /// Encode packet to a pooled buffer
    ///
    /// Returns a `PooledBuffer` that will be returned to the thread-local pool when dropped.
    /// This is more efficient than `encode()` when encoding many packets.
    pub fn encode_pooled(&self) -> PooledBuffer {
        let pool = BufferPool::new();
        let mut buf = pool.get_with_capacity(HOP_HDR_LEN + self.payload.len());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Encode packet into an existing buffer
    ///
    /// The buffer will be cleared before writing. Returns the number of bytes written.
    /// This is the most efficient encoding method when you can reuse a buffer.
    pub fn encode_into(&self, buf: &mut Vec<u8>) -> usize {
        buf.clear();
        buf.reserve(HOP_HDR_LEN + self.payload.len());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.payload);
        buf.len()
    }

    /// Encode packet with noise into an existing buffer
    ///
    /// The buffer will be cleared before writing. Returns the number of bytes written.
    pub fn encode_with_noise_into(&self, max_noise: usize, buf: &mut Vec<u8>) -> usize {
        use rand::Rng;

        buf.clear();
        let noise_len = if max_noise > 0 {
            rand::thread_rng().gen_range(0..=max_noise)
        } else {
            0
        };
        buf.reserve(HOP_HDR_LEN + self.payload.len() + noise_len);
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.payload);

        if noise_len > 0 {
            buf.extend((0..noise_len).map(|_| rand::random::<u8>()));
        }

        buf.len()
    }

    /// Parse handshake response payload (legacy IPv4 format)
    /// Returns (protocol_version, ip, mask)
    /// For v1 protocol or when you need raw IPv4 bytes
    pub fn parse_handshake_response(&self) -> Result<(u8, [u8; 4], u8)> {
        let (version, ip, mask) = self.parse_handshake_response_v2()?;
        match ip.as_ipv4_bytes() {
            Some(bytes) => Ok((version, bytes, mask)),
            None => Err(Error::Handshake(
                "expected IPv4 address but got IPv6".to_string(),
            )),
        }
    }

    /// Parse handshake response payload with IPv4/IPv6 support (single address)
    /// Returns (protocol_version, ip, mask)
    /// Wire format v2/v3: [version: 1] [count: 1] [addr...]
    /// For backwards compatibility, returns only the primary address
    pub fn parse_handshake_response_v2(&self) -> Result<(u8, crate::IpAddress, u8)> {
        let (version, addresses) = self.parse_handshake_response_v3()?;
        let primary = addresses.primary();
        Ok((version, primary.ip, primary.mask))
    }

    /// Parse handshake response payload with multi-address support
    /// Returns (protocol_version, assigned_addresses)
    /// Wire format v3: [version: 1] [count: 1] [addr1] [addr2] ...
    /// Each addr: [ip_type: 1] [ip: 4 or 16] [mask: 1]
    pub fn parse_handshake_response_v3(&self) -> Result<(u8, crate::AssignedAddresses)> {
        if self.payload.len() < 2 {
            return Err(Error::Handshake(
                "handshake response too short".to_string(),
            ));
        }

        let version = self.payload[0];

        // Decode the addresses
        let (addresses, _consumed) = crate::AssignedAddresses::decode(&self.payload[1..])?;

        Ok((version, addresses))
    }

    /// Parse handshake response payload with v4 DNS support
    /// Returns (protocol_version, handshake_response) where handshake_response contains
    /// both assigned addresses and DNS servers
    /// Wire format v4: [version: 1] [addr_count: 1] [addrs...] [dns_count: 1] [dns_ips...]
    /// For backwards compatibility, if DNS section is missing, returns empty dns_servers
    pub fn parse_handshake_response_v4(&self) -> Result<(u8, crate::HandshakeResponse)> {
        if self.payload.len() < 2 {
            return Err(Error::Handshake(
                "handshake response too short".to_string(),
            ));
        }

        let version = self.payload[0];

        // Decode the full response including DNS
        let (response, _consumed) = crate::HandshakeResponse::decode(&self.payload[1..])?;

        Ok((version, response))
    }

    /// Parse handshake error message
    pub fn parse_handshake_error(&self) -> String {
        String::from_utf8_lossy(&self.payload).to_string()
    }

    /// Get session ID from knock/handshake payload
    pub fn parse_sid_payload(&self) -> Result<u32> {
        if self.payload.len() < 4 {
            return Err(Error::InvalidPacket);
        }
        Ok(u32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let header = PacketHeader {
            flag: Flags::handshake().with_ack(),
            seq: 12345,
            plen: 100,
            frag_prefix: 50,
            frag: 1,
            sid: 0xDEADBEEF,
            dlen: 50,
        };

        let encoded = header.encode();
        assert_eq!(encoded.len(), HOP_HDR_LEN);

        let decoded = PacketHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_packet_encode_decode() {
        let packet = Packet::data(42, 0x12345678, vec![1, 2, 3, 4, 5]);

        let encoded = packet.encode();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_packet_with_noise() {
        let packet = Packet::data(1, 0x1234, vec![0xAA, 0xBB]);
        let encoded = packet.encode_with_noise(100);

        // Should decode correctly despite noise
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(packet.payload, decoded.payload);
        assert_eq!(packet.header, decoded.header);
    }

    #[test]
    fn test_handshake_packets() {
        // Handshake request
        let req = Packet::handshake_request(0x1234);
        assert!(req.header.flag.is_handshake());
        assert!(!req.header.flag.is_ack());

        // Handshake response with IPv4
        let resp = Packet::handshake_response(0x1234, [10, 1, 1, 3], 24);
        assert!(resp.header.flag.is_handshake_ack());

        let (version, ip, mask) = resp.parse_handshake_response().unwrap();
        assert_eq!(version, crate::HOP_PROTO_VERSION);
        assert_eq!(ip, [10, 1, 1, 3]);
        assert_eq!(mask, 24);

        // IPv4 handshake payload: version(1) + count(1) + type(1) + ip(4) + mask(1) = 8 bytes
        assert_eq!(resp.payload.len(), 8);
    }

    #[test]
    fn test_handshake_packets_ipv6() {
        use crate::IpAddress;

        // Handshake response with IPv6
        let ipv6 = IpAddress::from_ipv6_bytes([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x64, // 2001:db8::64
        ]);
        let resp = Packet::handshake_response_with_ip(0x5678, ipv6, 64);
        assert!(resp.header.flag.is_handshake_ack());

        // IPv6 handshake payload: version(1) + count(1) + type(1) + ip(16) + mask(1) = 20 bytes
        assert_eq!(resp.payload.len(), 20);

        // Parse using v2 method
        let (version, parsed_ip, mask) = resp.parse_handshake_response_v2().unwrap();
        assert_eq!(version, crate::HOP_PROTO_VERSION);
        assert_eq!(parsed_ip, ipv6);
        assert_eq!(mask, 64);

        // Legacy parse should fail for IPv6
        assert!(resp.parse_handshake_response().is_err());
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        use crate::IpAddress;

        // IPv4 roundtrip
        let ipv4 = IpAddress::from_ipv4_bytes([192, 168, 1, 100]);
        let resp4 = Packet::handshake_response_with_ip(0x1111, ipv4, 24);
        let (_, parsed4, mask4) = resp4.parse_handshake_response_v2().unwrap();
        assert_eq!(parsed4, ipv4);
        assert_eq!(mask4, 24);

        // IPv6 roundtrip
        let ipv6 = IpAddress::from_ipv6_bytes([
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        let resp6 = Packet::handshake_response_with_ip(0x2222, ipv6, 128);
        let (_, parsed6, mask6) = resp6.parse_handshake_response_v2().unwrap();
        assert_eq!(parsed6, ipv6);
        assert_eq!(mask6, 128);
    }

    #[test]
    fn test_handshake_multi_ip() {
        use crate::{AssignedAddress, AssignedAddresses, IpAddress};

        // Multi-address handshake response
        let addresses = AssignedAddresses::multiple(vec![
            AssignedAddress::from_ipv4([10, 0, 0, 1], 24),
            AssignedAddress::from_ipv4([192, 168, 1, 1], 24),
            AssignedAddress::from_ipv6(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                64,
            ),
        ])
        .unwrap();

        let resp = Packet::handshake_response_multi_ip(0xABCD, addresses.clone());
        assert!(resp.header.flag.is_handshake_ack());

        // Payload: version(1) + count(1) + 2*ipv4(6) + 1*ipv6(18) = 32 bytes
        assert_eq!(resp.payload.len(), 32);

        // Parse using v3 method
        let (version, parsed_addrs) = resp.parse_handshake_response_v3().unwrap();
        assert_eq!(version, crate::HOP_PROTO_VERSION);
        assert_eq!(parsed_addrs.len(), 3);
        assert_eq!(parsed_addrs.primary().ip, IpAddress::from_ipv4_bytes([10, 0, 0, 1]));

        // v2 should return only primary address
        let (_, primary_ip, primary_mask) = resp.parse_handshake_response_v2().unwrap();
        assert_eq!(primary_ip, IpAddress::from_ipv4_bytes([10, 0, 0, 1]));
        assert_eq!(primary_mask, 24);
    }

    #[test]
    fn test_knock_packet() {
        let sid = 0xCAFEBABE;
        let knock = Packet::knock(sid);

        assert!(knock.header.flag.is_push());
        assert_eq!(knock.parse_sid_payload().unwrap(), sid);
    }

    #[test]
    fn test_handshake_v4_with_dns() {
        use crate::{AssignedAddresses, IpAddress};

        let addresses = AssignedAddresses::single(IpAddress::from_ipv4_bytes([10, 0, 0, 1]), 24);
        let dns_servers = vec![
            IpAddress::from_ipv4_bytes([8, 8, 8, 8]),
            IpAddress::from_ipv4_bytes([1, 1, 1, 1]),
        ];

        let resp = Packet::handshake_response_v4(0x1234, addresses.clone(), dns_servers.clone());
        assert!(resp.header.flag.is_handshake_ack());

        // Payload: version(1) + count(1) + ipv4(6) + dns_count(1) + 2*dns_ipv4(5) = 19 bytes
        assert_eq!(resp.payload.len(), 19);

        // Parse using v4 method
        let (version, response) = resp.parse_handshake_response_v4().unwrap();
        assert_eq!(version, crate::HOP_PROTO_VERSION);
        assert_eq!(response.addresses, addresses);
        assert_eq!(response.dns_servers, dns_servers);
    }

    #[test]
    fn test_handshake_v4_no_dns() {
        use crate::{AssignedAddresses, IpAddress};

        let addresses = AssignedAddresses::single(IpAddress::from_ipv4_bytes([10, 0, 0, 1]), 24);

        let resp = Packet::handshake_response_v4(0x1234, addresses.clone(), vec![]);
        assert!(resp.header.flag.is_handshake_ack());

        // Payload: version(1) + count(1) + ipv4(6) + dns_count(1) = 9 bytes
        assert_eq!(resp.payload.len(), 9);

        // Parse using v4 method
        let (version, response) = resp.parse_handshake_response_v4().unwrap();
        assert_eq!(version, crate::HOP_PROTO_VERSION);
        assert_eq!(response.addresses, addresses);
        assert!(response.dns_servers.is_empty());
    }

    #[test]
    fn test_handshake_v4_backward_compat() {
        use crate::{AssignedAddresses, IpAddress};

        // Create a v3 style packet (multi_ip, no DNS)
        let addresses = AssignedAddresses::single(IpAddress::from_ipv4_bytes([10, 0, 0, 1]), 24);
        let resp = Packet::handshake_response_multi_ip(0x1234, addresses.clone());

        // Parse using v4 method - should work and return empty DNS
        let (version, response) = resp.parse_handshake_response_v4().unwrap();
        assert_eq!(version, crate::HOP_PROTO_VERSION);
        assert_eq!(response.addresses, addresses);
        assert!(response.dns_servers.is_empty());
    }

    // ========================================================================
    // Pooled buffer tests
    // ========================================================================

    #[test]
    fn test_encode_pooled() {
        let packet = Packet::data(42, 0x12345678, vec![1, 2, 3, 4, 5]);
        let encoded = packet.encode_pooled();

        // Should produce same output as regular encode
        assert_eq!(&encoded[..], &packet.encode()[..]);
    }

    #[test]
    fn test_encode_into() {
        let packet = Packet::data(42, 0x12345678, vec![1, 2, 3, 4, 5]);
        let mut buf = Vec::new();

        let len = packet.encode_into(&mut buf);
        assert_eq!(len, buf.len());
        assert_eq!(&buf[..], &packet.encode()[..]);

        // Test reuse - buffer should be cleared
        let packet2 = Packet::data(100, 0xABCD, vec![0xFF; 10]);
        let len2 = packet2.encode_into(&mut buf);
        assert_eq!(len2, buf.len());
        assert_eq!(&buf[..], &packet2.encode()[..]);
    }

    #[test]
    fn test_encode_with_noise_into() {
        let packet = Packet::data(42, 0x12345678, vec![1, 2, 3, 4, 5]);
        let mut buf = Vec::new();

        let len = packet.encode_with_noise_into(100, &mut buf);
        assert_eq!(len, buf.len());

        // Should decode correctly
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(packet.header, decoded.header);
        assert_eq!(packet.payload, decoded.payload);
    }

    #[test]
    fn test_encode_pooled_roundtrip() {
        let original = Packet::data(999, 0xDEADBEEF, vec![0xCA, 0xFE, 0xBA, 0xBE]);
        let encoded = original.encode_pooled();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_into_multiple_packets() {
        let mut buf = Vec::with_capacity(4096);

        // Encode multiple packets into the same buffer
        for i in 0..100u32 {
            let packet = Packet::data(i, i * 1000, vec![i as u8; (i % 50) as usize]);
            packet.encode_into(&mut buf);
            let decoded = Packet::decode(&buf).unwrap();
            assert_eq!(packet, decoded);
        }
    }
}
