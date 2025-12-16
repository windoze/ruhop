//! TUN device configuration

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::DEFAULT_MTU;

/// IPv4 address configuration for a TUN device
#[derive(Debug, Clone)]
pub struct Ipv4Config {
    /// The IPv4 address to assign to the interface
    pub address: Ipv4Addr,
    /// Network prefix length (e.g., 24 for /24)
    pub prefix_len: u8,
    /// Optional destination/peer address for point-to-point links
    pub destination: Option<Ipv4Addr>,
}

impl Ipv4Config {
    /// Create a new IPv4 configuration
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            address,
            prefix_len,
            destination: None,
        }
    }

    /// Set the destination/peer address
    pub fn with_destination(mut self, dest: Ipv4Addr) -> Self {
        self.destination = Some(dest);
        self
    }

    /// Get the network mask as an Ipv4Addr
    pub fn netmask(&self) -> Ipv4Addr {
        if self.prefix_len == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }
        if self.prefix_len >= 32 {
            return Ipv4Addr::new(255, 255, 255, 255);
        }
        let mask = !((1u32 << (32 - self.prefix_len)) - 1);
        Ipv4Addr::from(mask)
    }

    /// Get the network address
    pub fn network(&self) -> Ipv4Addr {
        let addr: u32 = self.address.into();
        let mask: u32 = self.netmask().into();
        Ipv4Addr::from(addr & mask)
    }
}

/// IPv6 address configuration for a TUN device
#[derive(Debug, Clone)]
pub struct Ipv6Config {
    /// The IPv6 address to assign to the interface
    pub address: Ipv6Addr,
    /// Network prefix length (e.g., 64 for /64)
    pub prefix_len: u8,
}

impl Ipv6Config {
    /// Create a new IPv6 configuration
    pub fn new(address: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            address,
            prefix_len,
        }
    }
}

/// Configuration for creating a TUN device
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name (optional, auto-generated if not specified)
    pub name: Option<String>,
    /// IPv4 configuration
    pub ipv4: Option<Ipv4Config>,
    /// IPv6 configurations (can have multiple)
    pub ipv6: Vec<Ipv6Config>,
    /// Maximum transmission unit
    pub mtu: u16,
    /// Whether to bring the interface up automatically
    pub up: bool,
    /// Enable packet information header (Linux only)
    pub packet_info: bool,
    /// Enable multi-queue (Linux only)
    pub multi_queue: bool,
    /// Number of queues for multi-queue mode
    pub num_queues: u8,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            ipv4: None,
            ipv6: Vec::new(),
            mtu: DEFAULT_MTU,
            up: true,
            packet_info: false,
            multi_queue: false,
            num_queues: 1,
        }
    }
}

impl TunConfig {
    /// Create a new configuration builder
    pub fn builder() -> TunConfigBuilder {
        TunConfigBuilder::new()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Must have at least one IP address
        if self.ipv4.is_none() && self.ipv6.is_empty() {
            return Err(Error::Config(
                "at least one IPv4 or IPv6 address must be configured".into(),
            ));
        }

        // Validate IPv4 prefix
        if let Some(ref ipv4) = self.ipv4 {
            if ipv4.prefix_len > 32 {
                return Err(Error::InvalidPrefix(format!(
                    "IPv4 prefix length {} is invalid (max 32)",
                    ipv4.prefix_len
                )));
            }
        }

        // Validate IPv6 prefixes
        for ipv6 in &self.ipv6 {
            if ipv6.prefix_len > 128 {
                return Err(Error::InvalidPrefix(format!(
                    "IPv6 prefix length {} is invalid (max 128)",
                    ipv6.prefix_len
                )));
            }
        }

        // Validate MTU
        if self.mtu < 68 {
            return Err(Error::Config(format!(
                "MTU {} is too small (minimum 68)",
                self.mtu
            )));
        }

        // Note: u16 max is 65535, so no need to check upper bound

        // Validate multi-queue settings
        if self.multi_queue && self.num_queues == 0 {
            return Err(Error::Config(
                "num_queues must be at least 1 when multi_queue is enabled".into(),
            ));
        }

        Ok(())
    }
}

/// Builder for TunConfig
#[derive(Debug, Default)]
pub struct TunConfigBuilder {
    config: TunConfig,
}

impl TunConfigBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface name
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.config.name = Some(name.into());
        self
    }

    /// Set the IPv4 address and prefix length
    pub fn ipv4(mut self, address: impl Into<Ipv4Addr>, prefix_len: u8) -> Self {
        self.config.ipv4 = Some(Ipv4Config::new(address.into(), prefix_len));
        self
    }

    /// Set the IPv4 address from a string (e.g., "10.0.0.1")
    pub fn ipv4_str(self, address: &str, prefix_len: u8) -> Result<Self> {
        let addr: Ipv4Addr = address
            .parse()
            .map_err(|_| Error::InvalidAddress(address.to_string()))?;
        Ok(self.ipv4(addr, prefix_len))
    }

    /// Set the IPv4 address with a destination for point-to-point
    pub fn ipv4_with_dest(
        mut self,
        address: impl Into<Ipv4Addr>,
        prefix_len: u8,
        dest: impl Into<Ipv4Addr>,
    ) -> Self {
        self.config.ipv4 = Some(Ipv4Config::new(address.into(), prefix_len).with_destination(dest.into()));
        self
    }

    /// Add an IPv6 address and prefix length
    pub fn ipv6(mut self, address: impl Into<Ipv6Addr>, prefix_len: u8) -> Self {
        self.config.ipv6.push(Ipv6Config::new(address.into(), prefix_len));
        self
    }

    /// Add an IPv6 address from a string
    pub fn ipv6_str(self, address: &str, prefix_len: u8) -> Result<Self> {
        let addr: Ipv6Addr = address
            .parse()
            .map_err(|_| Error::InvalidAddress(address.to_string()))?;
        Ok(self.ipv6(addr, prefix_len))
    }

    /// Set the MTU
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.config.mtu = mtu;
        self
    }

    /// Set whether to bring the interface up automatically
    pub fn up(mut self, up: bool) -> Self {
        self.config.up = up;
        self
    }

    /// Enable packet information header (Linux only)
    pub fn packet_info(mut self, enabled: bool) -> Self {
        self.config.packet_info = enabled;
        self
    }

    /// Enable multi-queue mode (Linux only)
    pub fn multi_queue(mut self, enabled: bool, num_queues: u8) -> Self {
        self.config.multi_queue = enabled;
        self.config.num_queues = num_queues;
        self
    }

    /// Build and validate the configuration
    pub fn build(self) -> Result<TunConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_netmask() {
        let config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 1), 24);
        assert_eq!(config.netmask(), Ipv4Addr::new(255, 255, 255, 0));

        let config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 1), 16);
        assert_eq!(config.netmask(), Ipv4Addr::new(255, 255, 0, 0));

        let config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 1), 32);
        assert_eq!(config.netmask(), Ipv4Addr::new(255, 255, 255, 255));

        let config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 1), 0);
        assert_eq!(config.netmask(), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_ipv4_network() {
        let config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 100), 24);
        assert_eq!(config.network(), Ipv4Addr::new(10, 0, 0, 0));

        let config = Ipv4Config::new(Ipv4Addr::new(192, 168, 1, 50), 16);
        assert_eq!(config.network(), Ipv4Addr::new(192, 168, 0, 0));
    }

    #[test]
    fn test_config_builder() {
        let config = TunConfig::builder()
            .name("tun0")
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24)
            .mtu(1400)
            .build()
            .unwrap();

        assert_eq!(config.name, Some("tun0".to_string()));
        assert_eq!(config.mtu, 1400);
        assert!(config.ipv4.is_some());
    }

    #[test]
    fn test_config_validation_no_address() {
        let result = TunConfig::builder().name("tun0").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_invalid_prefix() {
        let result = TunConfig::builder()
            .name("tun0")
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), 33)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_invalid_mtu() {
        let result = TunConfig::builder()
            .name("tun0")
            .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24)
            .mtu(10)
            .build();
        assert!(result.is_err());
    }
}
