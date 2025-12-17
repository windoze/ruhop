//! DNS proxy functionality for the VPN server
//!
//! This module provides:
//! - DNS client with support for UDP, TCP, DoH, and DoT
//! - DNS proxy server that listens on the tunnel IP
//! - TTL-based response caching
//! - Load balancing across multiple upstream DNS servers

mod cache;
mod client;
mod config;
mod proxy;

pub use cache::DnsCache;
pub use client::DnsClient;
pub use config::{DnsServerSpec, parse_dns_server};
pub use proxy::DnsProxy;
