//! IP address pool for dynamic VPN address allocation
//!
//! The pool allocates client addresses sequentially, starting from offset 2
//! (reserving offset 1 for the server's TUN interface).
//!
//! For example, from a /24 subnet like 10.1.1.0/24:
//! - Server TUN IP: 10.1.1.1 (not managed by pool, configured separately)
//! - Client 1: 10.1.1.2
//! - Client 2: 10.1.1.3
//! - Client 3: 10.1.1.4
//! - etc.

use crate::{AssignedAddress, IpAddress};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv4 address pool for allocating VPN client addresses
#[derive(Debug)]
pub struct Ipv4Pool {
    /// Network address (e.g., 10.1.1.0)
    network: Ipv4Addr,
    /// Subnet mask in CIDR notation (e.g., 24)
    mask: u8,
    /// Set of allocated address indices (offset from network)
    allocated: HashSet<u32>,
    /// Total number of client addresses available (excluding network, broadcast, and server)
    total_clients: u32,
}

impl Ipv4Pool {
    /// Create a new IPv4 pool from a network/mask specification
    ///
    /// The pool allocates addresses starting from network+2:
    /// - network+0: network address (reserved)
    /// - network+1: server TUN IP (reserved, configured separately)
    /// - network+2: first client
    /// - network+3: second client
    /// - etc.
    /// - broadcast: reserved
    ///
    /// # Example
    /// ```
    /// use hop_protocol::Ipv4Pool;
    /// let pool = Ipv4Pool::new([10, 1, 1, 0], 24).unwrap();
    /// ```
    pub fn new(network: [u8; 4], mask: u8) -> crate::Result<Self> {
        if mask > 30 {
            return Err(crate::Error::Pool(
                "subnet too small for VPN (need at least /30)".to_string(),
            ));
        }

        let network = Ipv4Addr::from(network);
        let host_bits = 32 - mask;
        // Number of usable addresses: 2^host_bits - 2 (network + broadcast)
        // Minus 1 more for server TUN IP
        let total_clients = (1u32 << host_bits).saturating_sub(3);

        Ok(Self {
            network,
            mask,
            allocated: HashSet::new(),
            total_clients,
        })
    }

    /// Create from CIDR notation string (e.g., "10.1.1.0/24")
    pub fn from_cidr(cidr: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(crate::Error::Pool(format!(
                "invalid CIDR notation: {}",
                cidr
            )));
        }

        let ip: Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| crate::Error::Pool(format!("invalid IPv4 address: {}", parts[0])))?;

        let mask: u8 = parts[1]
            .parse()
            .map_err(|_| crate::Error::Pool(format!("invalid mask: {}", parts[1])))?;

        Self::new(ip.octets(), mask)
    }

    /// Get the number of available (unallocated) client addresses
    pub fn available(&self) -> u32 {
        self.total_clients - self.allocated.len() as u32
    }

    /// Get the total number of client addresses in the pool
    pub fn total(&self) -> u32 {
        self.total_clients
    }

    /// Get the number of allocated addresses
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if the pool is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.allocated.len() as u32 >= self.total_clients
    }

    /// Allocate a client address from the pool
    ///
    /// Returns an assigned address for a client's TUN interface.
    pub fn allocate(&mut self) -> crate::Result<AssignedAddress> {
        if self.is_exhausted() {
            return Err(crate::Error::Pool("address pool exhausted".to_string()));
        }

        // Find first available client index (0-based, maps to network+2)
        let client_idx = (0..self.total_clients)
            .find(|idx| !self.allocated.contains(idx))
            .ok_or_else(|| crate::Error::Pool("address pool exhausted".to_string()))?;

        self.allocated.insert(client_idx);

        Ok(self.address_from_index(client_idx))
    }

    /// Release a client address back to the pool
    pub fn release(&mut self, addr: &IpAddress) -> bool {
        let ip = match addr {
            IpAddress::V4(v4) => v4,
            IpAddress::V6(_) => return false,
        };

        if let Some(client_idx) = self.index_from_ip(ip) {
            self.allocated.remove(&client_idx)
        } else {
            false
        }
    }

    /// Check if an address is allocated
    pub fn is_allocated(&self, addr: &IpAddress) -> bool {
        let ip = match addr {
            IpAddress::V4(v4) => v4,
            IpAddress::V6(_) => return false,
        };

        if let Some(client_idx) = self.index_from_ip(ip) {
            self.allocated.contains(&client_idx)
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

    /// Convert client index to address
    fn address_from_index(&self, client_idx: u32) -> AssignedAddress {
        let network_u32 = u32::from_be_bytes(self.network.octets());
        // Client index 0 -> network+2, index 1 -> network+3, etc.
        let client_ip = Ipv4Addr::from((network_u32 + client_idx + 2).to_be_bytes());
        AssignedAddress::new(IpAddress::V4(client_ip), self.mask)
    }

    /// Convert IP address to client index
    fn index_from_ip(&self, ip: &Ipv4Addr) -> Option<u32> {
        let network_u32 = u32::from_be_bytes(self.network.octets());
        let ip_u32 = u32::from_be_bytes(ip.octets());

        // Client addresses start at network+2
        if ip_u32 < network_u32 + 2 {
            return None;
        }

        let client_idx = ip_u32 - network_u32 - 2;
        if client_idx >= self.total_clients {
            return None;
        }

        Some(client_idx)
    }
}

/// IPv6 address pool for allocating VPN client addresses
#[derive(Debug)]
pub struct Ipv6Pool {
    /// Network prefix (e.g., 2001:db8:1::)
    network: Ipv6Addr,
    /// Prefix length in CIDR notation (e.g., 64)
    prefix_len: u8,
    /// Set of allocated client indices
    allocated: HashSet<u64>,
    /// Maximum number of clients to allocate (to prevent excessive memory use)
    max_clients: u64,
}

impl Ipv6Pool {
    /// Create a new IPv6 pool from a network/prefix specification
    ///
    /// # Arguments
    /// * `network` - The network prefix bytes
    /// * `prefix_len` - The prefix length (typically 64 or shorter)
    /// * `max_clients` - Maximum number of clients to allow (prevents memory exhaustion)
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
    pub fn new(network: [u8; 16], prefix_len: u8, max_clients: u64) -> crate::Result<Self> {
        if prefix_len > 126 {
            return Err(crate::Error::Pool(
                "prefix too long for VPN (need at least /126)".to_string(),
            ));
        }

        let network = Ipv6Addr::from(network);

        Ok(Self {
            network,
            prefix_len,
            allocated: HashSet::new(),
            max_clients,
        })
    }

    /// Create from CIDR notation string (e.g., "2001:db8:1::/64")
    pub fn from_cidr(cidr: &str, max_clients: u64) -> crate::Result<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(crate::Error::Pool(format!(
                "invalid CIDR notation: {}",
                cidr
            )));
        }

        let ip: Ipv6Addr = parts[0]
            .parse()
            .map_err(|_| crate::Error::Pool(format!("invalid IPv6 address: {}", parts[0])))?;

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| crate::Error::Pool(format!("invalid prefix length: {}", parts[1])))?;

        Self::new(ip.octets(), prefix_len, max_clients)
    }

    /// Get the number of available (unallocated) client addresses
    pub fn available(&self) -> u64 {
        self.max_clients.saturating_sub(self.allocated.len() as u64)
    }

    /// Get the maximum number of clients
    pub fn max_clients(&self) -> u64 {
        self.max_clients
    }

    /// Get the number of allocated addresses
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if the pool is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.allocated.len() as u64 >= self.max_clients
    }

    /// Allocate a client address from the pool
    pub fn allocate(&mut self) -> crate::Result<AssignedAddress> {
        if self.is_exhausted() {
            return Err(crate::Error::Pool("address pool exhausted".to_string()));
        }

        // Find first available client index
        let client_idx = (0..self.max_clients)
            .find(|idx| !self.allocated.contains(idx))
            .ok_or_else(|| crate::Error::Pool("address pool exhausted".to_string()))?;

        self.allocated.insert(client_idx);

        Ok(self.address_from_index(client_idx))
    }

    /// Release a client address back to the pool
    pub fn release(&mut self, addr: &IpAddress) -> bool {
        let ip = match addr {
            IpAddress::V4(_) => return false,
            IpAddress::V6(v6) => v6,
        };

        if let Some(client_idx) = self.index_from_ip(ip) {
            self.allocated.remove(&client_idx)
        } else {
            false
        }
    }

    /// Check if an address is allocated
    pub fn is_allocated(&self, addr: &IpAddress) -> bool {
        let ip = match addr {
            IpAddress::V4(_) => return false,
            IpAddress::V6(v6) => v6,
        };

        if let Some(client_idx) = self.index_from_ip(ip) {
            self.allocated.contains(&client_idx)
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

    /// Convert client index to address
    fn address_from_index(&self, client_idx: u64) -> AssignedAddress {
        let network_u128 = u128::from_be_bytes(self.network.octets());
        // Client index 0 -> network+2, index 1 -> network+3, etc.
        let client_ip = Ipv6Addr::from((network_u128 + client_idx as u128 + 2).to_be_bytes());
        AssignedAddress::new(IpAddress::V6(client_ip), self.prefix_len)
    }

    /// Convert IP address to client index
    fn index_from_ip(&self, ip: &Ipv6Addr) -> Option<u64> {
        let network_u128 = u128::from_be_bytes(self.network.octets());
        let ip_u128 = u128::from_be_bytes(ip.octets());

        // Client addresses start at network+2
        if ip_u128 < network_u128 + 2 {
            return None;
        }

        let client_idx = (ip_u128 - network_u128 - 2) as u64;
        if client_idx >= self.max_clients {
            return None;
        }

        Some(client_idx)
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
    pub fn new_v6(network: [u8; 16], prefix_len: u8, max_clients: u64) -> crate::Result<Self> {
        Ok(IpPool::V6(Ipv6Pool::new(network, prefix_len, max_clients)?))
    }

    /// Create from CIDR notation (auto-detects IPv4 vs IPv6)
    pub fn from_cidr(cidr: &str, max_v6_clients: u64) -> crate::Result<Self> {
        if cidr.contains(':') {
            Ok(IpPool::V6(Ipv6Pool::from_cidr(cidr, max_v6_clients)?))
        } else {
            Ok(IpPool::V4(Ipv4Pool::from_cidr(cidr)?))
        }
    }

    /// Allocate a client address
    pub fn allocate(&mut self) -> crate::Result<AssignedAddress> {
        match self {
            IpPool::V4(pool) => pool.allocate(),
            IpPool::V6(pool) => pool.allocate(),
        }
    }

    /// Release a client address
    pub fn release(&mut self, addr: &IpAddress) -> bool {
        match self {
            IpPool::V4(pool) => pool.release(addr),
            IpPool::V6(pool) => pool.release(addr),
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
        // /24 has 256 addresses - network - broadcast - server = 253 clients
        assert_eq!(pool.total(), 253);
        assert_eq!(pool.available(), 253);
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

        // First client gets .2
        let addr1 = pool.allocate().unwrap();
        assert_eq!(addr1.ip, IpAddress::V4(Ipv4Addr::new(10, 1, 1, 2)));
        assert_eq!(addr1.mask, 24);

        // Second client gets .3
        let addr2 = pool.allocate().unwrap();
        assert_eq!(addr2.ip, IpAddress::V4(Ipv4Addr::new(10, 1, 1, 3)));

        // Third client gets .4
        let addr3 = pool.allocate().unwrap();
        assert_eq!(addr3.ip, IpAddress::V4(Ipv4Addr::new(10, 1, 1, 4)));

        assert_eq!(pool.allocated_count(), 3);
        assert_eq!(pool.available(), 250);
    }

    #[test]
    fn test_ipv4_pool_release() {
        let mut pool = Ipv4Pool::new([10, 1, 1, 0], 24).unwrap();

        let addr1 = pool.allocate().unwrap();
        let addr2 = pool.allocate().unwrap();

        assert!(pool.is_allocated(&addr1.ip));
        assert!(pool.is_allocated(&addr2.ip));

        // Release first address
        assert!(pool.release(&addr1.ip));
        assert!(!pool.is_allocated(&addr1.ip));
        assert!(pool.is_allocated(&addr2.ip));

        // Release second address
        assert!(pool.release(&addr2.ip));
        assert!(!pool.is_allocated(&addr2.ip));

        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn test_ipv4_pool_exhaustion() {
        // /30 subnet: 4 addresses - network - broadcast - server = 1 client
        let mut pool = Ipv4Pool::new([10, 1, 1, 0], 30).unwrap();
        assert_eq!(pool.total(), 1);

        let _addr = pool.allocate().unwrap();
        assert!(pool.is_exhausted());

        let result = pool.allocate();
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_pool_reallocation() {
        let mut pool = Ipv4Pool::new([10, 1, 1, 0], 30).unwrap();

        let addr = pool.allocate().unwrap();
        assert!(pool.is_exhausted());

        pool.release(&addr.ip);
        assert!(!pool.is_exhausted());

        let addr2 = pool.allocate().unwrap();
        assert_eq!(addr, addr2); // Same address reused
    }

    #[test]
    fn test_ipv4_pool_small_subnets() {
        // /31 is too small (no room for clients after server)
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
        assert_eq!(pool.max_clients(), 1000);
    }

    #[test]
    fn test_ipv6_pool_from_cidr() {
        let pool = Ipv6Pool::from_cidr("2001:db8:1::/64", 500).unwrap();
        assert_eq!(pool.prefix_len(), 64);
    }

    #[test]
    fn test_ipv6_pool_allocation() {
        let mut pool = Ipv6Pool::from_cidr("2001:db8:1::/64", 100).unwrap();

        // First client gets ::2
        let addr1 = pool.allocate().unwrap();
        assert!(addr1.ip.is_ipv6());
        let expected_client1 = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2);
        assert_eq!(addr1.ip, IpAddress::V6(expected_client1));

        // Second client gets ::3
        let addr2 = pool.allocate().unwrap();
        let expected_client2 = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 3);
        assert_eq!(addr2.ip, IpAddress::V6(expected_client2));
    }

    #[test]
    fn test_ipv6_pool_release() {
        let mut pool = Ipv6Pool::from_cidr("2001:db8:1::/64", 100).unwrap();

        let addr = pool.allocate().unwrap();
        assert!(pool.is_allocated(&addr.ip));

        assert!(pool.release(&addr.ip));
        assert!(!pool.is_allocated(&addr.ip));
    }

    #[test]
    fn test_unified_pool() {
        let mut v4_pool = IpPool::new_v4([10, 0, 0, 0], 24).unwrap();
        assert!(v4_pool.is_ipv4());

        let addr = v4_pool.allocate().unwrap();
        assert!(addr.ip.is_ipv4());

        let mut v6_pool = IpPool::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
            100,
        )
        .unwrap();
        assert!(v6_pool.is_ipv6());

        let addr = v6_pool.allocate().unwrap();
        assert!(addr.ip.is_ipv6());
    }

    #[test]
    fn test_pool_from_cidr_auto_detect() {
        let v4 = IpPool::from_cidr("10.0.0.0/24", 100).unwrap();
        assert!(v4.is_ipv4());

        let v6 = IpPool::from_cidr("2001:db8::/64", 100).unwrap();
        assert!(v6.is_ipv6());
    }
}
