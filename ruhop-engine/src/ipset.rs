//! IP set management for DNS proxy (Linux only)
//!
//! This module provides functionality to add resolved IP addresses to IP sets.
//! It supports two backends:
//! - nftables (preferred): Uses the `nft` command
//! - ipset (fallback): Uses the legacy `ipset` command
//!
//! The backend is auto-detected at runtime.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// IP set backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsetBackend {
    /// nftables backend (uses `nft` command)
    Nftables,
    /// Legacy ipset backend (uses `ipset` command)
    Ipset,
}

impl IpsetBackend {
    /// Detect the available backend
    ///
    /// Tries nftables first, then falls back to ipset.
    pub fn detect() -> Option<Self> {
        // Try nftables first
        if Command::new("nft")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(IpsetBackend::Nftables);
        }

        // Fallback to ipset
        if Command::new("ipset")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(IpsetBackend::Ipset);
        }

        None
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
}

impl IpsetManager {
    /// Create a new IP set manager
    ///
    /// Automatically detects the available backend and creates the set if needed.
    ///
    /// # Arguments
    /// * `set_name` - Name of the IP set to use
    ///
    /// # Errors
    /// Returns an error if no backend is available or set creation fails.
    pub fn new(set_name: &str) -> Result<Self, String> {
        let backend = IpsetBackend::detect()
            .ok_or_else(|| "neither nft nor ipset command is available".to_string())?;

        let manager = Self {
            backend,
            set_name: set_name.to_string(),
            table_name: "ruhop".to_string(),
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
        // Check if set already exists
        let check = Command::new("nft")
            .args(["list", "set", "ip", &self.table_name, &self.set_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if check.map(|s| s.success()).unwrap_or(false) {
            log::debug!(
                "nftables set {}.{} already exists",
                self.table_name,
                self.set_name
            );
            return Ok(());
        }

        // Create table and set
        let nft_script = format!(
            "add table ip {table}\nadd set ip {table} {set} {{ type ipv4_addr; }}\n",
            table = self.table_name,
            set = self.set_name,
        );

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to run nft: {}", e))?;

        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(nft_script.as_bytes())
                .map_err(|e| format!("failed to write nft script: {}", e))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed to wait for nft: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "failed to create nftables set: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        log::info!(
            "Created nftables set {}.{}",
            self.table_name,
            self.set_name
        );
        Ok(())
    }

    /// Ensure ipset set exists
    fn ensure_ipset_set(&self) -> Result<(), String> {
        // Create set (uses -exist to avoid error if already exists)
        let output = Command::new("ipset")
            .args(["create", &self.set_name, "hash:ip", "-exist"])
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("failed to run ipset: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "failed to create ipset: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        log::debug!("Ensured ipset {} exists", self.set_name);
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

    /// Add IPs using nftables
    fn add_ips_nftables(&self, ips: &[std::net::Ipv4Addr]) {
        let elements: Vec<_> = ips.iter().map(|ip| ip.to_string()).collect();
        let nft_cmd = format!(
            "add element ip {} {} {{ {} }}\n",
            self.table_name,
            self.set_name,
            elements.join(", ")
        );

        let result = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(nft_cmd.as_bytes())?;
                }
                child.wait_with_output()
            });

        match result {
            Ok(output) if output.status.success() => {
                log::debug!(
                    "Added {} IP(s) to nftables set {}.{}",
                    ips.len(),
                    self.table_name,
                    self.set_name
                );
            }
            Ok(output) => {
                log::warn!(
                    "Failed to add IPs to nftables set: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                log::warn!("Failed to run nft command: {}", e);
            }
        }
    }

    /// Add IPs using ipset
    fn add_ips_ipset(&self, ips: &[std::net::Ipv4Addr]) {
        // Use ipset restore for batch adding
        let mut restore_script = String::new();
        for ip in ips {
            restore_script.push_str(&format!("add {} {} -exist\n", self.set_name, ip));
        }

        let result = Command::new("ipset")
            .arg("restore")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(restore_script.as_bytes())?;
                }
                child.wait_with_output()
            });

        match result {
            Ok(output) if output.status.success() => {
                log::debug!("Added {} IP(s) to ipset {}", ips.len(), self.set_name);
            }
            Ok(output) => {
                log::warn!(
                    "Failed to add IPs to ipset: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                log::warn!("Failed to run ipset command: {}", e);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_name() {
        assert_eq!(IpsetBackend::Nftables.name(), "nftables");
        assert_eq!(IpsetBackend::Ipset.name(), "ipset");
    }

    #[test]
    fn test_backend_detect() {
        // This test just ensures detection doesn't panic
        // The result depends on the system
        let _backend = IpsetBackend::detect();
    }
}
