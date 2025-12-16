//! Ruhop App Interface
//!
//! This crate provides a reusable VPN engine interface that can be used
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
//! │  │              ruhop-app-interface                        │ │
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
pub mod engine;
pub mod error;
pub mod event;
pub mod script;

pub use config::{ClientConfig, Config, ServerConfig};
pub use engine::{VpnEngine, VpnRole};
pub use error::{Error, Result};
pub use event::{VpnEvent, VpnState, VpnStats};
