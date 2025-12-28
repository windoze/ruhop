//! Ruhop Engine
//!
//! This crate provides a reusable VPN engine that can be used
//! by both CLI and GUI applications to manage VPN connections.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Application Layer                        │
//! │  ┌─────────────────┐              ┌─────────────────────┐   │
//! │  │   ruhop-cli     │              │   Future GUI App    │   │
//! │  └────────┬────────┘              └──────────┬──────────┘   │
//! │           │                                   │              │
//! │           └───────────────┬──────────────────┘              │
//! │                           ▼                                  │
//! │  ┌────────────────────────────────────────────────────────┐ │
//! │  │                   ruhop-engine                          │ │
//! │  │  - VpnEngine (main interface)                          │ │
//! │  │  - Config (TOML configuration)                         │ │
//! │  │  - Events (status updates, errors)                     │ │
//! │  └────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Library Layer                            │
//! │  ┌─────────────────┐    ┌─────────────────┐                │
//! │  │  hop-protocol   │    │    hop-tun      │                │
//! │  │  - Encryption   │    │  - TUN device   │                │
//! │  │  - Packets      │    │  - Routes       │                │
//! │  │  - Sessions     │    │  - NAT          │                │
//! │  └─────────────────┘    └─────────────────┘                │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod addr_stats;
pub mod config;
pub mod control;
pub mod engine;
pub mod error;
pub mod event;
#[cfg(target_os = "linux")]
pub mod ipset;
pub mod script;
pub mod socket;

pub use config::{
    ClientConfig, ClientDnsProxyConfig, Config, ProbeConfig, ServerAddress, ServerConfig,
};
pub use control::{
    ClientInfo, ClientsInfo, ControlClient, ControlRequest, ControlResponse, SharedStats,
    SharedStatsRef, StatusInfo, DEFAULT_SOCKET_PATH,
};
pub use engine::{VpnEngine, VpnRole};
pub use error::{Error, Result};
pub use event::{VpnEvent, VpnState, VpnStats};

// Re-export DNS types from hop-dns for convenience
pub use hop_dns::{parse_dns_server, CacheStats, DnsCache, DnsClient, DnsProxy, DnsServerSpec};
