//! IP address pool for dynamic VPN address allocation
//!
//! The pool allocates address pairs for point-to-point TUN tunnels:
//! - Client address: assigned to the client's TUN interface
//! - Server peer address: used as the server's endpoint in the tunnel
//!
//! For example, from a /24 subnet like 10.1.1.0/24:
//! - Pair 0: client=10.1.1.2, server_peer=10.1.1.1
//! - Pair 1: client=10.1.1.4, server_peer=10.1.1.3
//! - Pair 2: client=10.1.1.6, server_peer=10.1.1.5
//! - etc.

use crate::{AssignedAddress, IpAddress};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// An allocated address pair for a VPN tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressPair {
    /// Address assigned to the client's TUN interface
    pub client: AssignedAddress,
    /// Server's peer address for the tunnel (server's TUN endpoint)
    pub server_peer: AssignedAddress,
}

impl AddressPair {
    /// Create a new address pair
    pub fn new(client: AssignedAddress, server_peer: AssignedAddress) -> Self {
        Self { client, server_peer }
    }
}

impl std::fmt::Display for AddressPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "client={}, server_peer={}",
            self.client, self.server_peer
        )
    }
}

/// IPv4 address pool for allocating VPN address pairs
#[derive(Debug)]
pub struct Ipv4Pool {
    /// Network address (e.g., 10.1.1.0)
    network: Ipv4Addr,
    /// Subnet mask in CIDR notation (e.g., 24)
    mask: u8,
    /// Set of allocated pair indices
    allocated: HashSet<u32>,
    /// Total number of available pairs
    total_pairs: u32,
}

impl Ipv4Pool {
    /// Create a new IPv4 pool from a network/mask specification
    ///
    /// The pool allocates addresses in pairs:
    /// - First usable pair: (network+1, network+2) for (server_peer, client)
    /// - Second pair: (network+3, network+4)
    /// - etc.
    ///
    /// The network address and broadcast address are reserved.
    ///
    /// # Example
    /// ```
    /// use hop_protocol::Ipv4Pool;
    /// let pool = Ipv4Pool::new([10, 1, 1, 0], 24).unwrap();
    /// ```
    pub fn new(network: [u8; 4], mask: u8) -> crate::Result<Self> {
        if mask > 30 {
            return Err(crate::Error::Pool(
                "subnet too small for address pairs (need at least /30)".to_string(),
            ));
        }

        let network = Ipv4Addr::from(network);
        let host_bits = 32 - mask;
        // Number of usable addresses (excluding network and broadcast)
        let usable_addrs = (1u32 << host_bits) - 2;
        // Each tunnel needs 2 addresses (client + server_peer)
        let total_pairs = usable_addrs / 2;

        Ok(Self {
            network,
            mask,
            allocated: HashSet::new(),
            total_pairs,
        })
    }

    /// Create from CIDR notation string (e.g., "10.1.1.0/24")
    pub fn from_cidr(cidr: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(crate::Error::Pool(format!("invalid CIDR notation: {}", cidr)));
        }

        let ip: Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| crate::Error::Pool(format!("invalid IPv4 address: {}", parts[0])))?;

        let mask: u8 = parts[1]
            .parse()
            .map_err(|_| crate::Error::Pool(format!("invalid mask: {}", parts[1])))?;

        Self::new(ip.octets(), mask)
    }

    /// Get the number of available (unallocated) pairs
    pub fn available(&self) -> u32 {
        self.total_pairs - self.allocated.len() as u32
    }

    /// Get the total number of pairs in the pool
    pub fn total(&self) -> u32 {
        self.total_pairs
    }

    /// Get the number of allocated pairs
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if the pool is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.allocated.len() as u32 >= self.total_pairs
    }

    /// Allocate an address pair from the pool
    ///
    /// Returns a pair of addresses: (client_address, server_peer_address)
    /// The client address is the higher of the two in each pair.
    pub fn allocate(&mut self) -> crate::Result<AddressPair> {
        if self.is_exhausted() {
            return Err(crate::Error::Pool("address pool exhausted".to_string()));
        }

        // Find first available pair index
        let pair_idx = (0..self.total_pairs)
            .find(|idx| !self.allocated.contains(idx))
            .ok_or_else(|| crate::Error::Pool("address pool exhausted".to_string()))?;

        self.allocated.insert(pair_idx);

        Ok(self.pair_from_index(pair_idx))
    }

    /// Release an address pair back to the pool
    ///
    /// The address can be either the client or server_peer address from the pair.
    pub fn release(&mut self, addr: &IpAddress) -> bool {
        let ip = match addr {
            IpAddress::V4(v4) => v4,
            IpAddress::V6(_) => return false,
        };

        if let Some(pair_idx) = self.index_from_ip(ip) {
            self.allocated.remove(&pair_idx)
        } else {
            false
        }
    }

    /// Release a pair by the client address
    pub fn release_pair(&mut self, pair: &AddressPair) -> bool {
        self.release(&pair.client.ip)
    }

    /// Check if an address is allocated
    pub fn is_allocated(&self, addr: &IpAddress) -> bool {
        let ip = match addr {
            IpAddress::V4(v4) => v4,
            IpAddress::V6(_) => return false,
        };

        if let Some(pair_idx) = self.index_from_ip(ip) {
            self.allocated.contains(&pair_idx)
        } else {
            false
        }
    }

    /// Get the network address
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    /// Get the subnet mask
    pub fn mask(&self) -> u8 {
        self.mask
    }

    /// Convert pair index to address pair
    fn pair_from_index(&self, pair_idx: u32) -> AddressPair {
        let network_u32 = u32::from_be_bytes(self.network.octets());
        // Pair 0: addresses 1,2 (server_peer=1, client=2)
        // Pair 1: addresses 3,4 (server_peer=3, client=4)
        // etc.
        let server_peer_offset = pair_idx * 2 + 1;
        let client_offset = pair_idx * 2 + 2;

        let server_peer_ip = Ipv4Addr::from((network_u32 + server_peer_offset).to_be_bytes());
        let client_ip = Ipv4Addr::from((network_u32 + client_offset).to_be_bytes());

        // Use /32 for point-to-point addresses, but include the subnet mask for reference
        AddressPair {
            client: AssignedAddress::new(IpAddress::V4(client_ip), self.mask),
            server_peer: AssignedAddress::new(IpAddress::V4(server_peer_ip), self.mask),
        }
    }

    /// Convert IP address to pair index
    fn index_from_ip(&self, ip: &Ipv4Addr) -> Option<u32> {
        let network_u32 = u32::from_be_bytes(self.network.octets());
        let ip_u32 = u32::from_be_bytes(ip.octets());

        if ip_u32 <= network_u32 {
            return None;
        }

        let offset = ip_u32 - network_u32;
        if offset == 0 || offset > self.total_pairs * 2 {
            return None;
        }

        // offset 1,2 -> pair 0
        // offset 3,4 -> pair 1
        // etc.
        Some((offset - 1) / 2)
    }
}

/// IPv6 address pool for allocating VPN address pairs
#[derive(Debug)]
pub struct Ipv6Pool {
    /// Network prefix (e.g., 2001:db8:1::)
    network: Ipv6Addr,
    /// Prefix length in CIDR notation (e.g., 64)
    prefix_len: u8,
    /// Set of allocated pair indices
    allocated: HashSet<u64>,
    /// Maximum number of pairs to allocate (to prevent excessive memory use)
    max_pairs: u64,
}

impl Ipv6Pool {
    /// Create a new IPv6 pool from a network/prefix specification
    ///
    /// # Arguments
    /// * `network` - The network prefix bytes
    /// * `prefix_len` - The prefix length (typically 64 or shorter)
    /// * `max_pairs` - Maximum number of pairs to allow (prevents memory exhaustion)
    ///
    /// # Example
    /// ```
    /// use hop_protocol::Ipv6Pool;
    /// let pool = Ipv6Pool::new(
    ///     [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    ///     64,
    ///     10000,
    /// ).unwrap();
    /// ```
    pub fn new(network: [u8; 16], prefix_len: u8, max_pairs: u64) -> crate::Result<Self> {
        if prefix_len > 126 {
            return Err(crate::Error::Pool(
                "prefix too long for address pairs (need at least /126)".to_string(),
            ));
        }

        let network = Ipv6Addr::from(network);

        Ok(Self {
            network,
            prefix_len,
            allocated: HashSet::new(),
            max_pairs,
        })
    }

    /// Create from CIDR notation string (e.g., "2001:db8:1::/64")
    pub fn from_cidr(cidr: &str, max_pairs: u64) -> crate::Result<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(crate::Error::Pool(format!("invalid CIDR notation: {}", cidr)));
        }

        let ip: Ipv6Addr = parts[0]
            .parse()
            .map_err(|_| crate::Error::Pool(format!("invalid IPv6 address: {}", parts[0])))?;

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| crate::Error::Pool(format!("invalid prefix length: {}", parts[1])))?;

        Self::new(ip.octets(), prefix_len, max_pairs)
    }

    /// Get the number of available (unallocated) pairs
    pub fn available(&self) -> u64 {
        self.max_pairs.saturating_sub(self.allocated.len() as u64)
    }

    /// Get the maximum number of pairs
    pub fn max_pairs(&self) -> u64 {
        self.max_pairs
    }

    /// Get the number of allocated pairs
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if the pool is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.allocated.len() as u64 >= self.max_pairs
    }

    /// Allocate an address pair from the pool
    pub fn allocate(&mut self) -> crate::Result<AddressPair> {
        if self.is_exhausted() {
            return Err(crate::Error::Pool("address pool exhausted".to_string()));
        }

        // Find first available pair index
        let pair_idx = (0..self.max_pairs)
            .find(|idx| !self.allocated.contains(idx))
            .ok_or_else(|| crate::Error::Pool("address pool exhausted".to_string()))?;

        self.allocated.insert(pair_idx);

        Ok(self.pair_from_index(pair_idx))
    }

    /// Release an address pair back to the pool
    pub fn release(&mut self, addr: &IpAddress) -> bool {
        let ip = match addr {
            IpAddress::V4(_) => return false,
            IpAddress::V6(v6) => v6,
        };

        if let Some(pair_idx) = self.index_from_ip(ip) {
            self.allocated.remove(&pair_idx)
        } else {
            false
        }
    }

    /// Release a pair by the client address
    pub fn release_pair(&mut self, pair: &AddressPair) -> bool {
        self.release(&pair.client.ip)
    }

    /// Check if an address is allocated
    pub fn is_allocated(&self, addr: &IpAddress) -> bool {
        let ip = match addr {
            IpAddress::V4(_) => return false,
            IpAddress::V6(v6) => v6,
        };

        if let Some(pair_idx) = self.index_from_ip(ip) {
            self.allocated.contains(&pair_idx)
        } else {
            false
        }
    }

    /// Get the network prefix
    pub fn network(&self) -> Ipv6Addr {
        self.network
    }

    /// Get the prefix length
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Convert pair index to address pair
    fn pair_from_index(&self, pair_idx: u64) -> AddressPair {
        let network_u128 = u128::from_be_bytes(self.network.octets());
        let server_peer_offset = (pair_idx * 2 + 1) as u128;
        let client_offset = (pair_idx * 2 + 2) as u128;

        let server_peer_ip = Ipv6Addr::from((network_u128 + server_peer_offset).to_be_bytes());
        let client_ip = Ipv6Addr::from((network_u128 + client_offset).to_be_bytes());

        AddressPair {
            client: AssignedAddress::new(IpAddress::V6(client_ip), self.prefix_len),
            server_peer: AssignedAddress::new(IpAddress::V6(server_peer_ip), self.prefix_len),
        }
    }

    /// Convert IP address to pair index
    fn index_from_ip(&self, ip: &Ipv6Addr) -> Option<u64> {
        let network_u128 = u128::from_be_bytes(self.network.octets());
        let ip_u128 = u128::from_be_bytes(ip.octets());

        if ip_u128 <= network_u128 {
            return None;
        }

        let offset = ip_u128 - network_u128;
        if offset == 0 || offset > (self.max_pairs * 2) as u128 {
            return None;
        }

        // offset 1,2 -> pair 0
        // offset 3,4 -> pair 1
        Some(((offset - 1) / 2) as u64)
    }
}

/// A unified IP pool that can handle both IPv4 and IPv6
#[derive(Debug)]
pub enum IpPool {
    V4(Ipv4Pool),
    V6(Ipv6Pool),
}

impl IpPool {
    /// Create an IPv4 pool
    pub fn new_v4(network: [u8; 4], mask: u8) -> crate::Result<Self> {
        Ok(IpPool::V4(Ipv4Pool::new(network, mask)?))
    }

    /// Create an IPv6 pool
    pub fn new_v6(network: [u8; 16], prefix_len: u8, max_pairs: u64) -> crate::Result<Self> {
        Ok(IpPool::V6(Ipv6Pool::new(network, prefix_len, max_pairs)?))
    }

    /// Create from CIDR notation (auto-detects IPv4 vs IPv6)
    pub fn from_cidr(cidr: &str, max_v6_pairs: u64) -> crate::Result<Self> {
        if cidr.contains(':') {
            Ok(IpPool::V6(Ipv6Pool::from_cidr(cidr, max_v6_pairs)?))
        } else {
            Ok(IpPool::V4(Ipv4Pool::from_cidr(cidr)?))
        }
    }

    /// Allocate an address pair
    pub fn allocate(&mut self) -> crate::Result<AddressPair> {
        match self {
            IpPool::V4(pool) => pool.allocate(),
            IpPool::V6(pool) => pool.allocate(),
        }
    }

    /// Release an address pair
    pub fn release(&mut self, addr: &IpAddress) -> bool {
        match self {
            IpPool::V4(pool) => pool.release(addr),
            IpPool::V6(pool) => pool.release(addr),
        }
    }

    /// Release a pair
    pub fn release_pair(&mut self, pair: &AddressPair) -> bool {
        match self {
            IpPool::V4(pool) => pool.release_pair(pair),
            IpPool::V6(pool) => pool.release_pair(pair),
        }
    }

    /// Check if exhausted
    pub fn is_exhausted(&self) -> bool {
        match self {
            IpPool::V4(pool) => pool.is_exhausted(),
            IpPool::V6(pool) => pool.is_exhausted(),
        }
    }

    /// Check if an address is allocated
    pub fn is_allocated(&self, addr: &IpAddress) -> bool {
        match self {
            IpPool::V4(pool) => pool.is_allocated(addr),
            IpPool::V6(pool) => pool.is_allocated(addr),
        }
    }

    /// Check if this is an IPv4 pool
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpPool::V4(_))
    }

    /// Check if this is an IPv6 pool
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpPool::V6(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_pool_creation() {
        let pool = Ipv4Pool::new([10, 1, 1, 0], 24).unwrap();
        assert_eq!(pool.network(), Ipv4Addr::new(10, 1, 1, 0));
        assert_eq!(pool.mask(), 24);
        // /24 has 254 usable addresses, so 127 pairs
        assert_eq!(pool.total(), 127);
        assert_eq!(pool.available(), 127);
    }

    #[test]
    fn test_ipv4_pool_from_cidr() {
        let pool = Ipv4Pool::from_cidr("192.168.1.0/24").unwrap();
        assert_eq!(pool.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(pool.mask(), 24);
    }

    #[test]
    fn test_ipv4_pool_allocation() {
        let mut pool = Ipv4Pool::new([10, 1, 1, 0], 24).unwrap();

        let pair1 = pool.allocate().unwrap();
        assert_eq!(
            pair1.server_peer.ip,
            IpAddress::V4(Ipv4Addr::new(10, 1, 1, 1))
        );
        assert_eq!(pair1.client.ip, IpAddress::V4(Ipv4Addr::new(10, 1, 1, 2)));
        assert_eq!(pair1.client.mask, 24);

        let pair2 = pool.allocate().unwrap();
        assert_eq!(
            pair2.server_peer.ip,
            IpAddress::V4(Ipv4Addr::new(10, 1, 1, 3))
        );
        assert_eq!(pair2.client.ip, IpAddress::V4(Ipv4Addr::new(10, 1, 1, 4)));

        assert_eq!(pool.allocated_count(), 2);
        assert_eq!(pool.available(), 125);
    }

    #[test]
    fn test_ipv4_pool_release() {
        let mut pool = Ipv4Pool::new([10, 1, 1, 0], 24).unwrap();

        let pair1 = pool.allocate().unwrap();
        let pair2 = pool.allocate().unwrap();

        assert!(pool.is_allocated(&pair1.client.ip));
        assert!(pool.is_allocated(&pair1.server_peer.ip));

        // Release by client address
        assert!(pool.release(&pair1.client.ip));
        assert!(!pool.is_allocated(&pair1.client.ip));

        // Release by server_peer address
        assert!(pool.release(&pair2.server_peer.ip));
        assert!(!pool.is_allocated(&pair2.client.ip));

        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn test_ipv4_pool_exhaustion() {
        // /30 subnet: 2 usable addresses = 1 pair
        let mut pool = Ipv4Pool::new([10, 1, 1, 0], 30).unwrap();
        assert_eq!(pool.total(), 1);

        let _pair = pool.allocate().unwrap();
        assert!(pool.is_exhausted());

        let result = pool.allocate();
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_pool_reallocation() {
        let mut pool = Ipv4Pool::new([10, 1, 1, 0], 30).unwrap();

        let pair = pool.allocate().unwrap();
        assert!(pool.is_exhausted());

        pool.release_pair(&pair);
        assert!(!pool.is_exhausted());

        let pair2 = pool.allocate().unwrap();
        assert_eq!(pair, pair2); // Same addresses reused
    }

    #[test]
    fn test_ipv4_pool_small_subnets() {
        // /31 is too small
        assert!(Ipv4Pool::new([10, 1, 1, 0], 31).is_err());
        // /32 is too small
        assert!(Ipv4Pool::new([10, 1, 1, 0], 32).is_err());
    }

    #[test]
    fn test_ipv6_pool_creation() {
        let pool = Ipv6Pool::new(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
            1000,
        )
        .unwrap();
        assert_eq!(pool.prefix_len(), 64);
        assert_eq!(pool.max_pairs(), 1000);
    }

    #[test]
    fn test_ipv6_pool_from_cidr() {
        let pool = Ipv6Pool::from_cidr("2001:db8:1::/64", 500).unwrap();
        assert_eq!(pool.prefix_len(), 64);
    }

    #[test]
    fn test_ipv6_pool_allocation() {
        let mut pool = Ipv6Pool::from_cidr("2001:db8:1::/64", 100).unwrap();

        let pair1 = pool.allocate().unwrap();
        assert!(pair1.server_peer.ip.is_ipv6());
        assert!(pair1.client.ip.is_ipv6());

        // Server peer should be ::1, client should be ::2
        let expected_server = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
        let expected_client = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2);
        assert_eq!(pair1.server_peer.ip, IpAddress::V6(expected_server));
        assert_eq!(pair1.client.ip, IpAddress::V6(expected_client));

        let pair2 = pool.allocate().unwrap();
        let expected_server2 = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 3);
        let expected_client2 = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 4);
        assert_eq!(pair2.server_peer.ip, IpAddress::V6(expected_server2));
        assert_eq!(pair2.client.ip, IpAddress::V6(expected_client2));
    }

    #[test]
    fn test_ipv6_pool_release() {
        let mut pool = Ipv6Pool::from_cidr("2001:db8:1::/64", 100).unwrap();

        let pair = pool.allocate().unwrap();
        assert!(pool.is_allocated(&pair.client.ip));

        assert!(pool.release_pair(&pair));
        assert!(!pool.is_allocated(&pair.client.ip));
    }

    #[test]
    fn test_unified_pool() {
        let mut v4_pool = IpPool::new_v4([10, 0, 0, 0], 24).unwrap();
        assert!(v4_pool.is_ipv4());

        let pair = v4_pool.allocate().unwrap();
        assert!(pair.client.ip.is_ipv4());

        let mut v6_pool = IpPool::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
            100,
        )
        .unwrap();
        assert!(v6_pool.is_ipv6());

        let pair = v6_pool.allocate().unwrap();
        assert!(pair.client.ip.is_ipv6());
    }

    #[test]
    fn test_pool_from_cidr_auto_detect() {
        let v4 = IpPool::from_cidr("10.0.0.0/24", 100).unwrap();
        assert!(v4.is_ipv4());

        let v6 = IpPool::from_cidr("2001:db8::/64", 100).unwrap();
        assert!(v6.is_ipv6());
    }

    #[test]
    fn test_address_pair_display() {
        let pair = AddressPair {
            client: AssignedAddress::from_ipv4([10, 1, 1, 2], 24),
            server_peer: AssignedAddress::from_ipv4([10, 1, 1, 1], 24),
        };
        let display = format!("{}", pair);
        assert!(display.contains("10.1.1.2/24"));
        assert!(display.contains("10.1.1.1/24"));
    }
}
