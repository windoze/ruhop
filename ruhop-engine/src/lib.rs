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

pub mod config;
pub mod control;
pub mod dns;
pub mod engine;
pub mod error;
pub mod event;
pub mod script;
pub mod socket;

pub use config::{ClientConfig, Config, DnsConfig, ServerAddress, ServerConfig};
pub use control::{ControlClient, ControlRequest, ControlResponse, StatusInfo, ClientInfo, ClientsInfo, SharedStats, SharedStatsRef, DEFAULT_SOCKET_PATH};
pub use engine::{VpnEngine, VpnRole};
pub use error::{Error, Result};
pub use event::{VpnEvent, VpnState, VpnStats};
