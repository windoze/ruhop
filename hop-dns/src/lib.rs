//! hop-dns - DNS client with multi-protocol support
//!
//! This crate provides a DNS client that supports multiple protocols:
//! - UDP (traditional DNS)
//! - TCP
//! - DoH (DNS over HTTPS)
//! - DoT (DNS over TLS)
//!
//! Features:
//! - Configurable upstream selection strategies (first-reply, round-robin, random)
//! - TTL-based response caching
//! - DNS proxy server for forwarding queries
//!
//! # Example
//!
//! ```no_run
//! use hop_dns::{DnsClient, DnsServerSpec, UpstreamStrategy, parse_dns_server};
//!
//! # async fn example() -> hop_dns::Result<()> {
//! // Parse DNS server specs
//! let upstream = parse_dns_server("8.8.8.8")?;
//!
//! // Create a DNS client with default strategy (first-reply)
//! let client = DnsClient::new(vec![upstream.clone()], 1000)?;
//!
//! // Or with a specific strategy
//! let client = DnsClient::with_strategy(
//!     vec![upstream],
//!     1000,
//!     UpstreamStrategy::RoundRobin
//! )?;
//!
//! // Query DNS (raw DNS message bytes)
//! // let response = client.query(&dns_query_bytes).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Upstream Strategies
//!
//! - **FirstReply** (default): Sends queries to all upstreams in parallel and returns
//!   the first successful response. Best for latency-sensitive applications.
//! - **RoundRobin**: Selects upstreams in round-robin order. Good for even load distribution.
//! - **Random**: Selects a random upstream for each query.

mod cache;
mod client;
mod config;
pub mod error;
mod proxy;

pub use cache::{CacheStats, DnsCache};
pub use client::DnsClient;
pub use config::{DnsServerSpec, UpstreamStrategy, parse_dns_server};
pub use error::{Error, Result};
pub use proxy::{DnsProxy, ResolvedIps};
