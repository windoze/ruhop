//! IP address types for IPv4 and IPv6 support

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// IP address that can be either IPv4 or IPv6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddress {
    /// IPv4 address (4 bytes)
    V4(Ipv4Addr),
    /// IPv6 address (16 bytes)
    V6(Ipv6Addr),
}

impl IpAddress {
    /// Create an IPv4 address from bytes
    pub fn from_ipv4_bytes(bytes: [u8; 4]) -> Self {
        IpAddress::V4(Ipv4Addr::from(bytes))
    }

    /// Create an IPv6 address from bytes
    pub fn from_ipv6_bytes(bytes: [u8; 16]) -> Self {
        IpAddress::V6(Ipv6Addr::from(bytes))
    }

    /// Check if this is an IPv4 address
    pub const fn is_ipv4(&self) -> bool {
        matches!(self, IpAddress::V4(_))
    }

    /// Check if this is an IPv6 address
    pub const fn is_ipv6(&self) -> bool {
        matches!(self, IpAddress::V6(_))
    }

    /// Get the address as IPv4 bytes if it's IPv4
    pub fn as_ipv4_bytes(&self) -> Option<[u8; 4]> {
        match self {
            IpAddress::V4(addr) => Some(addr.octets()),
            IpAddress::V6(_) => None,
        }
    }

    /// Get the address as IPv6 bytes if it's IPv6
    pub fn as_ipv6_bytes(&self) -> Option<[u8; 16]> {
        match self {
            IpAddress::V4(_) => None,
            IpAddress::V6(addr) => Some(addr.octets()),
        }
    }

    /// Get the wire format length (4 for IPv4, 16 for IPv6)
    pub const fn wire_len(&self) -> usize {
        match self {
            IpAddress::V4(_) => 4,
            IpAddress::V6(_) => 16,
        }
    }

    /// Encode to wire format with type prefix
    /// Format: [type: 1 byte] [address: 4 or 16 bytes]
    /// Type: 0x04 for IPv4, 0x06 for IPv6
    pub fn encode(&self) -> Vec<u8> {
        match self {
            IpAddress::V4(addr) => {
                let mut buf = Vec::with_capacity(5);
                buf.push(0x04);
                buf.extend_from_slice(&addr.octets());
                buf
            }
            IpAddress::V6(addr) => {
                let mut buf = Vec::with_capacity(17);
                buf.push(0x06);
                buf.extend_from_slice(&addr.octets());
                buf
            }
        }
    }

    /// Decode from wire format with type prefix
    /// Returns (address, bytes_consumed)
    pub fn decode(buf: &[u8]) -> crate::Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(crate::Error::InvalidPacket);
        }

        match buf[0] {
            0x04 => {
                // IPv4
                if buf.len() < 5 {
                    return Err(crate::Error::InvalidPacket);
                }
                let bytes: [u8; 4] = buf[1..5].try_into().unwrap();
                Ok((IpAddress::from_ipv4_bytes(bytes), 5))
            }
            0x06 => {
                // IPv6
                if buf.len() < 17 {
                    return Err(crate::Error::InvalidPacket);
                }
                let bytes: [u8; 16] = buf[1..17].try_into().unwrap();
                Ok((IpAddress::from_ipv6_bytes(bytes), 17))
            }
            _ => Err(crate::Error::InvalidPacket),
        }
    }

    /// Convert to u128 for routing key generation
    /// IPv4 addresses are zero-extended to 128 bits
    pub fn to_u128(&self) -> u128 {
        match self {
            IpAddress::V4(addr) => u32::from_be_bytes(addr.octets()) as u128,
            IpAddress::V6(addr) => u128::from_be_bytes(addr.octets()),
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddress::V4(addr) => write!(f, "{}", addr),
            IpAddress::V6(addr) => write!(f, "{}", addr),
        }
    }
}

impl From<Ipv4Addr> for IpAddress {
    fn from(addr: Ipv4Addr) -> Self {
        IpAddress::V4(addr)
    }
}

impl From<Ipv6Addr> for IpAddress {
    fn from(addr: Ipv6Addr) -> Self {
        IpAddress::V6(addr)
    }
}

impl From<[u8; 4]> for IpAddress {
    fn from(bytes: [u8; 4]) -> Self {
        IpAddress::from_ipv4_bytes(bytes)
    }
}

impl From<[u8; 16]> for IpAddress {
    fn from(bytes: [u8; 16]) -> Self {
        IpAddress::from_ipv6_bytes(bytes)
    }
}

impl From<std::net::IpAddr> for IpAddress {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => IpAddress::V4(v4),
            std::net::IpAddr::V6(v6) => IpAddress::V6(v6),
        }
    }
}

impl From<IpAddress> for std::net::IpAddr {
    fn from(addr: IpAddress) -> Self {
        match addr {
            IpAddress::V4(v4) => std::net::IpAddr::V4(v4),
            IpAddress::V6(v6) => std::net::IpAddr::V6(v6),
        }
    }
}

/// An assigned address with its subnet mask/prefix length
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssignedAddress {
    /// The IP address
    pub ip: IpAddress,
    /// Subnet mask (0-32 for IPv4, 0-128 for IPv6)
    pub mask: u8,
}

impl AssignedAddress {
    /// Create a new assigned address
    pub fn new(ip: IpAddress, mask: u8) -> Self {
        Self { ip, mask }
    }

    /// Create from IPv4 bytes
    pub fn from_ipv4(ip: [u8; 4], mask: u8) -> Self {
        Self {
            ip: IpAddress::from_ipv4_bytes(ip),
            mask,
        }
    }

    /// Create from IPv6 bytes
    pub fn from_ipv6(ip: [u8; 16], mask: u8) -> Self {
        Self {
            ip: IpAddress::from_ipv6_bytes(ip),
            mask,
        }
    }

    /// Encode to wire format
    /// Format: [ip_type: 1] [ip: 4 or 16] [mask: 1]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.ip.encode();
        buf.push(self.mask);
        buf
    }

    /// Decode from wire format
    /// Returns (address, bytes_consumed)
    pub fn decode(buf: &[u8]) -> crate::Result<(Self, usize)> {
        let (ip, ip_consumed) = IpAddress::decode(buf)?;
        if buf.len() < ip_consumed + 1 {
            return Err(crate::Error::InvalidPacket);
        }
        let mask = buf[ip_consumed];
        Ok((Self { ip, mask }, ip_consumed + 1))
    }

    /// Get the wire format length
    pub fn wire_len(&self) -> usize {
        self.ip.wire_len() + 2 // type + ip + mask
    }
}

impl fmt::Display for AssignedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
    }
}

/// A collection of assigned addresses (for multi-homed servers)
/// The first address is the primary address used for TUN interface
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddresses {
    /// List of assigned addresses (at least one required)
    addresses: Vec<AssignedAddress>,
}

impl AssignedAddresses {
    /// Create from a single address (backwards compatible)
    pub fn single(ip: IpAddress, mask: u8) -> Self {
        Self {
            addresses: vec![AssignedAddress::new(ip, mask)],
        }
    }

    /// Create from multiple addresses
    /// Returns None if the list is empty
    pub fn multiple(addresses: Vec<AssignedAddress>) -> Option<Self> {
        if addresses.is_empty() {
            None
        } else {
            Some(Self { addresses })
        }
    }

    /// Get the primary (first) address - used for TUN interface
    pub fn primary(&self) -> &AssignedAddress {
        &self.addresses[0]
    }

    /// Get all addresses
    pub fn all(&self) -> &[AssignedAddress] {
        &self.addresses
    }

    /// Get the number of addresses
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Check if there's only one address
    pub fn is_single(&self) -> bool {
        self.addresses.len() == 1
    }

    /// Check if empty (should never be true after construction)
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Iterate over addresses
    pub fn iter(&self) -> impl Iterator<Item = &AssignedAddress> {
        self.addresses.iter()
    }

    /// Get all IPv4 addresses
    pub fn ipv4_addresses(&self) -> impl Iterator<Item = &AssignedAddress> {
        self.addresses.iter().filter(|a| a.ip.is_ipv4())
    }

    /// Get all IPv6 addresses
    pub fn ipv6_addresses(&self) -> impl Iterator<Item = &AssignedAddress> {
        self.addresses.iter().filter(|a| a.ip.is_ipv6())
    }

    /// Encode to wire format
    /// Format: [count: 1] [addr1] [addr2] ...
    /// Each addr: [ip_type: 1] [ip: 4 or 16] [mask: 1]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.addresses.len() as u8);
        for addr in &self.addresses {
            buf.extend_from_slice(&addr.encode());
        }
        buf
    }

    /// Decode from wire format
    /// Returns (addresses, bytes_consumed)
    pub fn decode(buf: &[u8]) -> crate::Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(crate::Error::InvalidPacket);
        }

        let count = buf[0] as usize;
        if count == 0 {
            return Err(crate::Error::Handshake(
                "handshake response has no addresses".to_string(),
            ));
        }

        let mut addresses = Vec::with_capacity(count);
        let mut offset = 1;

        for _ in 0..count {
            let (addr, consumed) = AssignedAddress::decode(&buf[offset..])?;
            addresses.push(addr);
            offset += consumed;
        }

        Ok((Self { addresses }, offset))
    }
}

impl IntoIterator for AssignedAddresses {
    type Item = AssignedAddress;
    type IntoIter = std::vec::IntoIter<AssignedAddress>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.into_iter()
    }
}

impl<'a> IntoIterator for &'a AssignedAddresses {
    type Item = &'a AssignedAddress;
    type IntoIter = std::slice::Iter<'a, AssignedAddress>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.iter()
    }
}

/// Handshake response data for protocol v4
/// Contains assigned addresses and optional DNS servers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// Assigned tunnel addresses
    pub addresses: AssignedAddresses,
    /// DNS servers to push to client (may be empty)
    pub dns_servers: Vec<IpAddress>,
}

impl HandshakeResponse {
    /// Create a handshake response without DNS servers (backwards compatible)
    pub fn new(addresses: AssignedAddresses) -> Self {
        Self {
            addresses,
            dns_servers: Vec::new(),
        }
    }

    /// Create a handshake response with DNS servers
    pub fn with_dns(addresses: AssignedAddresses, dns_servers: Vec<IpAddress>) -> Self {
        Self {
            addresses,
            dns_servers,
        }
    }

    /// Encode to wire format (v4)
    /// Format: [addr_count: 1] [addrs...] [dns_count: 1] [dns_ips...]
    /// DNS section is only included if dns_servers is non-empty
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.addresses.encode();

        // Always include DNS count for v4 protocol
        buf.push(self.dns_servers.len() as u8);
        for dns in &self.dns_servers {
            buf.extend_from_slice(&dns.encode());
        }

        buf
    }

    /// Decode from wire format (v4)
    /// Returns (response, bytes_consumed)
    /// For backwards compatibility with v3, if there's no DNS section, returns empty dns_servers
    pub fn decode(buf: &[u8]) -> crate::Result<(Self, usize)> {
        // First decode addresses
        let (addresses, addr_consumed) = AssignedAddresses::decode(buf)?;

        // Check if there's a DNS section
        if buf.len() <= addr_consumed {
            // No DNS section (v3 compatibility)
            return Ok((
                Self {
                    addresses,
                    dns_servers: Vec::new(),
                },
                addr_consumed,
            ));
        }

        let dns_count = buf[addr_consumed] as usize;
        let mut offset = addr_consumed + 1;
        let mut dns_servers = Vec::with_capacity(dns_count);

        for _ in 0..dns_count {
            if offset >= buf.len() {
                return Err(crate::Error::InvalidPacket);
            }
            let (ip, consumed) = IpAddress::decode(&buf[offset..])?;
            dns_servers.push(ip);
            offset += consumed;
        }

        Ok((
            Self {
                addresses,
                dns_servers,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_roundtrip() {
        let addr = IpAddress::from_ipv4_bytes([10, 1, 1, 100]);
        assert!(addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert_eq!(addr.as_ipv4_bytes(), Some([10, 1, 1, 100]));
        assert_eq!(addr.wire_len(), 4);
        assert_eq!(format!("{}", addr), "10.1.1.100");

        let encoded = addr.encode();
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], 0x04);

        let (decoded, consumed) = IpAddress::decode(&encoded).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_ipv6_roundtrip() {
        let addr = IpAddress::from_ipv6_bytes([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        assert!(addr.is_ipv6());
        assert!(!addr.is_ipv4());
        assert_eq!(addr.wire_len(), 16);
        assert_eq!(format!("{}", addr), "2001:db8::1");

        let encoded = addr.encode();
        assert_eq!(encoded.len(), 17);
        assert_eq!(encoded[0], 0x06);

        let (decoded, consumed) = IpAddress::decode(&encoded).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(consumed, 17);
    }

    #[test]
    fn test_to_u128() {
        let v4 = IpAddress::from_ipv4_bytes([10, 0, 0, 1]);
        assert_eq!(v4.to_u128(), 0x0A000001);

        let v6 = IpAddress::from_ipv6_bytes([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        assert_eq!(v6.to_u128(), 1);
    }

    #[test]
    fn test_conversions() {
        let v4 = Ipv4Addr::new(192, 168, 1, 1);
        let addr: IpAddress = v4.into();
        assert!(addr.is_ipv4());

        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr: IpAddress = v6.into();
        assert!(addr.is_ipv6());

        let std_addr = std::net::IpAddr::V4(v4);
        let addr: IpAddress = std_addr.into();
        assert!(addr.is_ipv4());

        let converted: std::net::IpAddr = addr.into();
        assert_eq!(converted, std_addr);
    }

    #[test]
    fn test_assigned_address_roundtrip() {
        let addr = AssignedAddress::from_ipv4([10, 1, 1, 100], 24);
        assert_eq!(format!("{}", addr), "10.1.1.100/24");

        let encoded = addr.encode();
        // type(1) + ip(4) + mask(1) = 6 bytes
        assert_eq!(encoded.len(), 6);

        let (decoded, consumed) = AssignedAddress::decode(&encoded).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(consumed, 6);

        // IPv6
        let addr6 = AssignedAddress::from_ipv6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            64,
        );
        let encoded6 = addr6.encode();
        // type(1) + ip(16) + mask(1) = 18 bytes
        assert_eq!(encoded6.len(), 18);

        let (decoded6, consumed6) = AssignedAddress::decode(&encoded6).unwrap();
        assert_eq!(decoded6, addr6);
        assert_eq!(consumed6, 18);
    }

    #[test]
    fn test_assigned_addresses_single() {
        let addrs = AssignedAddresses::single(IpAddress::from_ipv4_bytes([10, 0, 0, 1]), 24);
        assert_eq!(addrs.len(), 1);
        assert!(addrs.is_single());
        assert_eq!(
            addrs.primary().ip,
            IpAddress::from_ipv4_bytes([10, 0, 0, 1])
        );
        assert_eq!(addrs.primary().mask, 24);

        let encoded = addrs.encode();
        // count(1) + type(1) + ip(4) + mask(1) = 7 bytes
        assert_eq!(encoded.len(), 7);
        assert_eq!(encoded[0], 1); // count

        let (decoded, consumed) = AssignedAddresses::decode(&encoded).unwrap();
        assert_eq!(decoded, addrs);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_assigned_addresses_multiple() {
        let addresses = vec![
            AssignedAddress::from_ipv4([10, 0, 0, 1], 24),
            AssignedAddress::from_ipv4([192, 168, 1, 1], 24),
            AssignedAddress::from_ipv6(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                64,
            ),
        ];

        let addrs = AssignedAddresses::multiple(addresses).unwrap();
        assert_eq!(addrs.len(), 3);
        assert!(!addrs.is_single());
        assert_eq!(
            addrs.primary().ip,
            IpAddress::from_ipv4_bytes([10, 0, 0, 1])
        );

        // Check filtering
        assert_eq!(addrs.ipv4_addresses().count(), 2);
        assert_eq!(addrs.ipv6_addresses().count(), 1);

        // Roundtrip
        let encoded = addrs.encode();
        // count(1) + 2*ipv4(6) + 1*ipv6(18) = 1 + 12 + 18 = 31 bytes
        assert_eq!(encoded.len(), 31);
        assert_eq!(encoded[0], 3); // count

        let (decoded, consumed) = AssignedAddresses::decode(&encoded).unwrap();
        assert_eq!(decoded, addrs);
        assert_eq!(consumed, 31);
    }

    #[test]
    fn test_assigned_addresses_empty_rejected() {
        assert!(AssignedAddresses::multiple(vec![]).is_none());

        // Decoding empty count should fail
        let buf = [0u8]; // count = 0
        assert!(AssignedAddresses::decode(&buf).is_err());
    }

    #[test]
    fn test_assigned_addresses_iteration() {
        let addrs = AssignedAddresses::multiple(vec![
            AssignedAddress::from_ipv4([10, 0, 0, 1], 24),
            AssignedAddress::from_ipv4([10, 0, 0, 2], 24),
        ])
        .unwrap();

        let ips: Vec<_> = addrs.iter().map(|a| a.ip).collect();
        assert_eq!(ips.len(), 2);

        // Test into_iter
        let mut count = 0;
        for _addr in &addrs {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_handshake_response_no_dns() {
        let addrs = AssignedAddresses::single(IpAddress::from_ipv4_bytes([10, 0, 0, 1]), 24);
        let response = HandshakeResponse::new(addrs.clone());

        assert!(response.dns_servers.is_empty());

        let encoded = response.encode();
        // count(1) + ipv4(6) + dns_count(1) = 8 bytes
        assert_eq!(encoded.len(), 8);

        let (decoded, consumed) = HandshakeResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.addresses, addrs);
        assert!(decoded.dns_servers.is_empty());
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_handshake_response_with_dns() {
        let addrs = AssignedAddresses::single(IpAddress::from_ipv4_bytes([10, 0, 0, 1]), 24);
        let dns = vec![
            IpAddress::from_ipv4_bytes([8, 8, 8, 8]),
            IpAddress::from_ipv4_bytes([8, 8, 4, 4]),
        ];
        let response = HandshakeResponse::with_dns(addrs.clone(), dns.clone());

        assert_eq!(response.dns_servers.len(), 2);

        let encoded = response.encode();
        // count(1) + ipv4(6) + dns_count(1) + 2*dns_ipv4(5) = 18 bytes
        assert_eq!(encoded.len(), 18);

        let (decoded, consumed) = HandshakeResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.addresses, addrs);
        assert_eq!(decoded.dns_servers, dns);
        assert_eq!(consumed, 18);
    }

    #[test]
    fn test_handshake_response_v3_compatibility() {
        // Test that v4 decoder can handle v3 format (no DNS section)
        let addrs = AssignedAddresses::single(IpAddress::from_ipv4_bytes([10, 0, 0, 1]), 24);
        let v3_encoded = addrs.encode();
        // count(1) + ipv4(6) = 7 bytes (no dns_count)
        assert_eq!(v3_encoded.len(), 7);

        let (decoded, consumed) = HandshakeResponse::decode(&v3_encoded).unwrap();
        assert_eq!(decoded.addresses, addrs);
        assert!(decoded.dns_servers.is_empty());
        assert_eq!(consumed, 7);
    }
}
