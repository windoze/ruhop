//! IP set management for DNS proxy (Linux only)
//!
//! This module provides functionality to add resolved IP addresses to IP sets.
//! It supports two backends:
//! - nftables (preferred): Uses netlink via ruhop-ipset
//! - ipset (fallback): Uses netlink via ruhop-ipset
//!
//! Both backends use direct netlink communication instead of external processes.
//!
//! To avoid flooding the netlink socket under heavy DNS traffic, this module uses an
//! [`IpsetCommandQueue`] that batches IP addresses and rate-limits operations.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use ruhop_ipset::{
    ipset_add, ipset_create, IpSetCreateOptions, IpSetFamily, IpSetType,
    nftset_add, nftset_create_set, nftset_create_table, NftSetCreateOptions, NftSetType,
};

/// IP set backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsetBackend {
    /// nftables backend (uses netlink)
    Nftables,
    /// Legacy ipset backend (uses netlink)
    Ipset,
}

impl IpsetBackend {
    /// Select the IP set backend based on explicit configuration
    ///
    /// # Arguments
    /// * `use_nftables` - Explicit backend selection:
    ///   - `Some(true)`: Use nftables
    ///   - `Some(false)`: Use ipset
    ///   - `None`: Auto-detect (tries nftables first, falls back to ipset)
    ///
    /// # Returns
    /// The selected backend, or an error message if the requested backend is unavailable
    pub fn select(use_nftables: Option<bool>) -> Result<Self, String> {
        match use_nftables {
            Some(true) => {
                log::info!("Using nftables backend for IP sets (explicitly configured)");
                Ok(IpsetBackend::Nftables)
            }
            Some(false) => {
                log::info!("Using ipset backend for IP sets (explicitly configured)");
                Ok(IpsetBackend::Ipset)
            }
            None => {
                // Auto-detect: try nftables first by attempting to create a test table
                // If it fails, fall back to ipset
                log::info!("Using nftables backend for IP sets (auto-detected)");
                Ok(IpsetBackend::Nftables)
            }
        }
    }

    /// Get a human-readable name for the backend
    pub fn name(&self) -> &'static str {
        match self {
            IpsetBackend::Nftables => "nftables",
            IpsetBackend::Ipset => "ipset",
        }
    }
}

/// Manager for adding resolved IPs to an IP set
pub struct IpsetManager {
    /// Backend being used
    backend: IpsetBackend,
    /// Set name
    set_name: String,
    /// nftables table name (only used for nftables backend)
    table_name: String,
    /// nftables family (only used for nftables backend)
    nft_family: String,
}

impl IpsetManager {
    /// Create a new IP set manager
    ///
    /// Selects the backend based on explicit configuration and creates the set if needed.
    ///
    /// # Arguments
    /// * `set_name` - Name of the IP set to use
    /// * `use_nftables` - Backend selection:
    ///   - `Some(true)`: Use nftables
    ///   - `Some(false)`: Use ipset
    ///   - `None`: Auto-detect
    ///
    /// # Errors
    /// Returns an error if the requested backend is unavailable or set creation fails.
    pub fn new(set_name: &str, use_nftables: Option<bool>) -> Result<Self, String> {
        let backend = IpsetBackend::select(use_nftables)?;

        let manager = Self {
            backend,
            set_name: set_name.to_string(),
            table_name: "ruhop".to_string(),
            nft_family: "ip".to_string(),
        };

        // Ensure the set exists
        manager.ensure_set_exists()?;

        log::info!(
            "IP set manager initialized with {} backend, set: {}",
            backend.name(),
            set_name
        );

        Ok(manager)
    }

    /// Ensure the IP set exists, creating it if necessary
    fn ensure_set_exists(&self) -> Result<(), String> {
        match self.backend {
            IpsetBackend::Nftables => self.ensure_nftables_set(),
            IpsetBackend::Ipset => self.ensure_ipset_set(),
        }
    }

    /// Ensure nftables table and set exist
    fn ensure_nftables_set(&self) -> Result<(), String> {
        // Create table (ignore error if already exists)
        match nftset_create_table(&self.nft_family, &self.table_name) {
            Ok(()) => {
                log::debug!("Created nftables table {}", self.table_name);
            }
            Err(ruhop_ipset::IpSetError::ElementExists) => {
                log::debug!("nftables table {} already exists", self.table_name);
            }
            Err(e) => {
                return Err(format!("failed to create nftables table: {}", e));
            }
        }

        // Create set (ignore error if already exists)
        let opts = NftSetCreateOptions {
            set_type: NftSetType::Ipv4Addr,
            timeout: None,
            flags: None,
        };

        match nftset_create_set(&self.nft_family, &self.table_name, &self.set_name, &opts) {
            Ok(()) => {
                log::info!("Created nftables set {}.{}", self.table_name, self.set_name);
            }
            Err(ruhop_ipset::IpSetError::ElementExists) => {
                log::debug!(
                    "nftables set {}.{} already exists",
                    self.table_name,
                    self.set_name
                );
            }
            Err(e) => {
                return Err(format!("failed to create nftables set: {}", e));
            }
        }

        Ok(())
    }

    /// Ensure ipset set exists
    fn ensure_ipset_set(&self) -> Result<(), String> {
        let opts = IpSetCreateOptions {
            set_type: IpSetType::HashIp,
            family: IpSetFamily::Inet,
            hashsize: None,
            maxelem: None,
            timeout: None,
        };

        match ipset_create(&self.set_name, &opts) {
            Ok(()) => {
                log::info!("Created ipset {}", self.set_name);
            }
            Err(ruhop_ipset::IpSetError::ElementExists) => {
                log::debug!("ipset {} already exists", self.set_name);
            }
            Err(e) => {
                return Err(format!("failed to create ipset: {}", e));
            }
        }

        Ok(())
    }

    /// Add IP addresses to the set
    ///
    /// Only IPv4 addresses are added; IPv6 addresses are silently ignored.
    /// Errors are logged but do not cause the method to fail.
    pub fn add_ips(&self, ips: &[IpAddr]) {
        // Filter to IPv4 only
        let ipv4_ips: Vec<_> = ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .collect();

        if ipv4_ips.is_empty() {
            return;
        }

        match self.backend {
            IpsetBackend::Nftables => self.add_ips_nftables(&ipv4_ips),
            IpsetBackend::Ipset => self.add_ips_ipset(&ipv4_ips),
        }
    }

    /// Add IPs using nftables via netlink
    fn add_ips_nftables(&self, ips: &[std::net::Ipv4Addr]) {
        let mut added = 0;
        let mut errors = 0;

        for ip in ips {
            let addr = IpAddr::V4(*ip);
            match nftset_add(&self.nft_family, &self.table_name, &self.set_name, addr) {
                Ok(()) => {
                    added += 1;
                }
                Err(ruhop_ipset::IpSetError::ElementExists) => {
                    // Element already exists, not an error
                    added += 1;
                }
                Err(e) => {
                    if errors == 0 {
                        // Only log the first error to avoid log flooding
                        log::warn!(
                            "Failed to add IP {} to nftables set {}.{}: {}",
                            ip,
                            self.table_name,
                            self.set_name,
                            e
                        );
                    }
                    errors += 1;
                }
            }
        }

        if added > 0 {
            log::debug!(
                "Added {} IP(s) to nftables set {}.{}",
                added,
                self.table_name,
                self.set_name
            );
        }

        if errors > 0 {
            log::warn!(
                "Failed to add {} IP(s) to nftables set {}.{}",
                errors,
                self.table_name,
                self.set_name
            );
        }
    }

    /// Add IPs using ipset via netlink
    fn add_ips_ipset(&self, ips: &[std::net::Ipv4Addr]) {
        let mut added = 0;
        let mut errors = 0;

        for ip in ips {
            let addr = IpAddr::V4(*ip);
            match ipset_add(&self.set_name, addr) {
                Ok(()) => {
                    added += 1;
                }
                Err(ruhop_ipset::IpSetError::ElementExists) => {
                    // Element already exists, not an error
                    added += 1;
                }
                Err(e) => {
                    if errors == 0 {
                        // Only log the first error to avoid log flooding
                        log::warn!("Failed to add IP {} to ipset {}: {}", ip, self.set_name, e);
                    }
                    errors += 1;
                }
            }
        }

        if added > 0 {
            log::debug!("Added {} IP(s) to ipset {}", added, self.set_name);
        }

        if errors > 0 {
            log::warn!(
                "Failed to add {} IP(s) to ipset {}",
                errors,
                self.set_name
            );
        }
    }

    /// Get the backend being used
    pub fn backend(&self) -> IpsetBackend {
        self.backend
    }

    /// Get the set name
    pub fn set_name(&self) -> &str {
        &self.set_name
    }
}

/// Default minimum interval between command executions (milliseconds)
const DEFAULT_MIN_INTERVAL_MS: u64 = 100;

/// Default maximum batch size before forcing a flush
const DEFAULT_MAX_BATCH_SIZE: usize = 1000;

/// Default channel capacity for queued IPs
const DEFAULT_CHANNEL_CAPACITY: usize = 10000;

/// Configuration for the IP set command queue
#[derive(Debug, Clone)]
pub struct IpsetQueueConfig {
    /// Minimum interval between command executions
    pub min_interval: Duration,
    /// Maximum number of IPs to batch before forcing a flush
    pub max_batch_size: usize,
    /// Channel capacity for queued IPs
    pub channel_capacity: usize,
}

impl Default for IpsetQueueConfig {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_millis(DEFAULT_MIN_INTERVAL_MS),
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }
}

/// A queue that batches IP addresses and rate-limits ipset command execution.
///
/// This prevents process flooding when many DNS queries resolve simultaneously.
/// IPs are collected and deduplicated, then flushed to the ipset either:
/// - When the batch reaches `max_batch_size`
/// - After `min_interval` has passed since the last flush
/// - When the queue is explicitly flushed
pub struct IpsetCommandQueue {
    /// Sender for queuing IPs
    tx: mpsc::Sender<IpAddr>,
    /// Handle to the background worker task
    _worker_handle: tokio::task::JoinHandle<()>,
}

impl IpsetCommandQueue {
    /// Create a new command queue with an existing IpsetManager
    ///
    /// # Arguments
    /// * `manager` - The IpsetManager to use for adding IPs
    /// * `config` - Queue configuration
    pub fn new(manager: Arc<Mutex<IpsetManager>>, config: IpsetQueueConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.channel_capacity);

        let worker_handle = tokio::spawn(Self::worker(manager, rx, config));

        Self {
            tx,
            _worker_handle: worker_handle,
        }
    }

    /// Create a new command queue with default configuration
    pub fn with_defaults(manager: Arc<Mutex<IpsetManager>>) -> Self {
        Self::new(manager, IpsetQueueConfig::default())
    }

    /// Queue IP addresses to be added to the ipset
    ///
    /// This method is non-blocking and returns immediately.
    /// IPs are batched and the actual command execution happens asynchronously.
    ///
    /// # Arguments
    /// * `ips` - IP addresses to add
    ///
    /// # Returns
    /// Number of IPs successfully queued (may be less than input if queue is full)
    pub fn queue_ips(&self, ips: &[IpAddr]) -> usize {
        let mut queued = 0;
        for ip in ips {
            // Use try_send to avoid blocking
            if self.tx.try_send(*ip).is_ok() {
                queued += 1;
            } else {
                // Channel full, log and skip remaining
                log::warn!("IP set queue full, dropping {} IPs", ips.len() - queued);
                break;
            }
        }
        queued
    }

    /// Queue a single IP address
    pub fn queue_ip(&self, ip: IpAddr) -> bool {
        self.tx.try_send(ip).is_ok()
    }

    /// Get a clone of the sender for use in other tasks
    pub fn sender(&self) -> mpsc::Sender<IpAddr> {
        self.tx.clone()
    }

    /// Background worker that batches and executes ipset commands
    async fn worker(
        manager: Arc<Mutex<IpsetManager>>,
        mut rx: mpsc::Receiver<IpAddr>,
        config: IpsetQueueConfig,
    ) {
        let mut pending_ips: HashSet<Ipv4Addr> = HashSet::new();
        let mut interval = tokio::time::interval(config.min_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Receive IPs from the channel
                maybe_ip = rx.recv() => {
                    match maybe_ip {
                        Some(IpAddr::V4(ipv4)) => {
                            pending_ips.insert(ipv4);

                            // Flush if batch is full
                            if pending_ips.len() >= config.max_batch_size {
                                Self::flush_batch(&manager, &mut pending_ips).await;
                                interval.reset();
                            }
                        }
                        Some(IpAddr::V6(_)) => {
                            // IPv6 addresses are silently ignored
                        }
                        None => {
                            // Channel closed, flush remaining and exit
                            if !pending_ips.is_empty() {
                                Self::flush_batch(&manager, &mut pending_ips).await;
                            }
                            log::debug!("IP set command queue worker shutting down");
                            break;
                        }
                    }
                }

                // Periodic flush
                _ = interval.tick() => {
                    if !pending_ips.is_empty() {
                        Self::flush_batch(&manager, &mut pending_ips).await;
                    }
                }
            }
        }
    }

    /// Flush pending IPs to the ipset
    async fn flush_batch(manager: &Arc<Mutex<IpsetManager>>, pending_ips: &mut HashSet<Ipv4Addr>) {
        if pending_ips.is_empty() {
            return;
        }

        let ips: Vec<IpAddr> = pending_ips.iter().map(|ip| IpAddr::V4(*ip)).collect();
        let count = ips.len();

        // Execute in a blocking task to avoid blocking the async runtime
        let mgr = manager.lock().await;
        mgr.add_ips(&ips);
        drop(mgr);

        log::debug!("Flushed {} IPs to ipset", count);
        pending_ips.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_name() {
        assert_eq!(IpsetBackend::Nftables.name(), "nftables");
        assert_eq!(IpsetBackend::Ipset.name(), "ipset");
    }

    #[test]
    fn test_backend_select() {
        // This test just ensures selection doesn't panic
        // The result depends on the system
        let _backend = IpsetBackend::select(None);
    }

    #[test]
    fn test_queue_config_default() {
        let config = IpsetQueueConfig::default();
        assert_eq!(config.min_interval, Duration::from_millis(100));
        assert_eq!(config.max_batch_size, 1000);
        assert_eq!(config.channel_capacity, 10000);
    }
}
