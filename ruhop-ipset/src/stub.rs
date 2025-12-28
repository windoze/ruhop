//! Stub implementations for non-Linux platforms.
//!
//! All functions return `Err(IpSetError::UnsupportedPlatform)`.

use crate::{IpEntry, IpSetError, Result};

/// ipset type for hash:ip sets (stub for non-Linux)
#[derive(Clone, Copy, Debug)]
pub enum IpSetType {
    /// hash:ip - stores IP addresses
    HashIp,
    /// hash:net - stores network addresses (CIDR)
    HashNet,
}

/// Address family for ipset (stub for non-Linux)
#[derive(Clone, Copy, Debug)]
pub enum IpSetFamily {
    /// IPv4 addresses
    Inet,
    /// IPv6 addresses
    Inet6,
}

/// Options for creating an ipset (stub for non-Linux)
#[derive(Clone, Debug, Default)]
pub struct IpSetCreateOptions {
    pub set_type: IpSetType,
    pub family: IpSetFamily,
    pub hashsize: Option<u32>,
    pub maxelem: Option<u32>,
    pub timeout: Option<u32>,
}

impl Default for IpSetType {
    fn default() -> Self {
        IpSetType::HashIp
    }
}

impl Default for IpSetFamily {
    fn default() -> Self {
        IpSetFamily::Inet
    }
}

/// Address type for nftables sets (stub for non-Linux)
#[derive(Clone, Copy, Debug)]
pub enum NftSetType {
    /// IPv4 addresses
    Ipv4Addr,
    /// IPv6 addresses
    Ipv6Addr,
}

impl Default for NftSetType {
    fn default() -> Self {
        NftSetType::Ipv4Addr
    }
}

/// Options for creating an nftables set (stub for non-Linux)
#[derive(Clone, Debug, Default)]
pub struct NftSetCreateOptions {
    pub set_type: NftSetType,
    pub timeout: Option<u32>,
    pub flags: Option<u32>,
}

// ipset stub functions

/// Create an ipset (stub - returns UnsupportedPlatform error)
pub fn ipset_create(_setname: &str, _options: &IpSetCreateOptions) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Destroy an ipset (stub - returns UnsupportedPlatform error)
pub fn ipset_destroy(_setname: &str) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Flush an ipset (stub - returns UnsupportedPlatform error)
pub fn ipset_flush(_setname: &str) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Add an IP to an ipset (stub - returns UnsupportedPlatform error)
pub fn ipset_add<E: Into<IpEntry>>(_setname: &str, _entry: E) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Delete an IP from an ipset (stub - returns UnsupportedPlatform error)
pub fn ipset_del<E: Into<IpEntry>>(_setname: &str, _entry: E) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Test if an IP exists in an ipset (stub - returns UnsupportedPlatform error)
pub fn ipset_test<E: Into<IpEntry>>(_setname: &str, _entry: E) -> Result<bool> {
    Err(IpSetError::UnsupportedPlatform)
}

// nftset stub functions

/// Create an nftables table (stub - returns UnsupportedPlatform error)
pub fn nftset_create_table(_family: &str, _table: &str) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Delete an nftables table (stub - returns UnsupportedPlatform error)
pub fn nftset_delete_table(_family: &str, _table: &str) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Create an nftables set (stub - returns UnsupportedPlatform error)
pub fn nftset_create_set(
    _family: &str,
    _table: &str,
    _setname: &str,
    _options: &NftSetCreateOptions,
) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Delete an nftables set (stub - returns UnsupportedPlatform error)
pub fn nftset_delete_set(_family: &str, _table: &str, _setname: &str) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Add an IP to an nftables set (stub - returns UnsupportedPlatform error)
pub fn nftset_add<E: Into<IpEntry>>(
    _family: &str,
    _table: &str,
    _setname: &str,
    _entry: E,
) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Delete an IP from an nftables set (stub - returns UnsupportedPlatform error)
pub fn nftset_del<E: Into<IpEntry>>(
    _family: &str,
    _table: &str,
    _setname: &str,
    _entry: E,
) -> Result<()> {
    Err(IpSetError::UnsupportedPlatform)
}

/// Test if an IP exists in an nftables set (stub - returns UnsupportedPlatform error)
pub fn nftset_test<E: Into<IpEntry>>(
    _family: &str,
    _table: &str,
    _setname: &str,
    _entry: E,
) -> Result<bool> {
    Err(IpSetError::UnsupportedPlatform)
}
