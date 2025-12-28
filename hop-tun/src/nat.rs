//! NAT/Masquerading setup for TUN devices
//!
//! This module provides functionality to set up NAT (Network Address Translation)
//! and IP masquerading for traffic flowing through TUN interfaces.
//!
//! # Platform Support
//!
//! - **Linux**: Uses nftables (preferred) or iptables (fallback) for NAT configuration
//! - **macOS**: Uses pf (Packet Filter) for NAT
//! - **Windows**: Uses Windows Firewall/NAT APIs
//!
//! # Security Note
//!
//! NAT configuration requires elevated privileges and modifies system firewall rules.
//! Always clean up NAT rules when the VPN connection terminates.

use std::net::IpAddr;
use std::process::Command;

use crate::error::{Error, Result};

/// Firewall backend for Linux systems
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    /// nftables (modern, preferred)
    Nftables,
    /// iptables (legacy)
    Iptables,
}

#[cfg(target_os = "linux")]
impl FirewallBackend {
    /// Select the firewall backend based on explicit configuration
    ///
    /// # Arguments
    /// * `use_nftables` - Explicit backend selection:
    ///   - `Some(true)`: Use nftables (fails if unavailable)
    ///   - `Some(false)`: Use iptables (fails if unavailable)
    ///   - `None`: Auto-detect (tries nftables first, falls back to iptables)
    ///
    /// # Returns
    /// The selected backend, or an error if the requested backend is unavailable
    pub fn select(use_nftables: Option<bool>) -> Result<Self> {
        match use_nftables {
            Some(true) => {
                // Explicitly requested nftables
                if Self::is_nftables_available() {
                    log::info!("Using nftables backend for firewall rules (explicitly configured)");
                    Ok(FirewallBackend::Nftables)
                } else {
                    Err(Error::Nat(
                        "nftables backend requested but 'nft' command is not available".into(),
                    ))
                }
            }
            Some(false) => {
                // Explicitly requested iptables
                if Self::is_iptables_available() {
                    log::info!("Using iptables backend for firewall rules (explicitly configured)");
                    Ok(FirewallBackend::Iptables)
                } else {
                    Err(Error::Nat(
                        "iptables backend requested but 'iptables' command is not available".into(),
                    ))
                }
            }
            None => {
                // Auto-detect: try nftables first, then iptables
                if Self::is_nftables_available() {
                    log::info!("Using nftables backend for firewall rules (auto-detected)");
                    Ok(FirewallBackend::Nftables)
                } else if Self::is_iptables_available() {
                    log::info!("Using iptables backend for firewall rules (auto-detected, nft not available)");
                    Ok(FirewallBackend::Iptables)
                } else {
                    Err(Error::Nat(
                        "no firewall backend available: neither 'nft' nor 'iptables' command found"
                            .into(),
                    ))
                }
            }
        }
    }

    /// Check if nftables is available
    fn is_nftables_available() -> bool {
        Command::new("nft")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if iptables is available
    fn is_iptables_available() -> bool {
        Command::new("iptables")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// The nftables table name used for ruhop NAT rules
#[cfg(target_os = "linux")]
const NFT_TABLE_NAME: &str = "ruhop";

/// NAT rule configuration
#[derive(Debug, Clone)]
pub struct NatRule {
    /// Source network to masquerade (CIDR)
    pub source: String,
    /// Outbound interface for NAT
    pub out_interface: String,
    /// Whether to enable SNAT vs MASQUERADE
    pub use_snat: bool,
    /// SNAT address (if use_snat is true)
    pub snat_address: Option<IpAddr>,
}

impl NatRule {
    /// Create a masquerade rule for a source network
    pub fn masquerade(source: impl Into<String>, out_interface: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            out_interface: out_interface.into(),
            use_snat: false,
            snat_address: None,
        }
    }

    /// Create a SNAT rule
    pub fn snat(
        source: impl Into<String>,
        out_interface: impl Into<String>,
        snat_address: IpAddr,
    ) -> Self {
        Self {
            source: source.into(),
            out_interface: out_interface.into(),
            use_snat: true,
            snat_address: Some(snat_address),
        }
    }
}

/// Manager for NAT/Masquerading rules
///
/// Provides cross-platform NAT configuration for VPN traffic.
pub struct NatManager {
    /// Applied rules for cleanup
    applied_rules: Vec<NatRule>,
    /// Whether IP forwarding was enabled by us
    enabled_forwarding: bool,
    /// Firewall backend (Linux only)
    #[cfg(target_os = "linux")]
    backend: FirewallBackend,
    /// Original IPv4 forwarding value (to restore on cleanup)
    #[cfg(target_os = "linux")]
    original_ipv4_forward: Option<String>,
    /// Original IPv6 forwarding value (to restore on cleanup)
    #[cfg(target_os = "linux")]
    original_ipv6_forward: Option<String>,
    /// Original macOS forwarding value (to restore on cleanup)
    #[cfg(target_os = "macos")]
    original_ip_forward: Option<String>,
    /// Original Windows forwarding value (to restore on cleanup)
    #[cfg(target_os = "windows")]
    original_ip_forward: Option<String>,
}

impl NatManager {
    /// Create a new NAT manager
    ///
    /// # Arguments
    /// * `use_nftables` - Firewall backend selection (Linux only):
    ///   - `Some(true)`: Use nftables
    ///   - `Some(false)`: Use iptables
    ///   - `None`: Auto-detect
    #[cfg(target_os = "linux")]
    pub fn new(use_nftables: Option<bool>) -> Result<Self> {
        let backend = FirewallBackend::select(use_nftables)?;
        Ok(Self {
            applied_rules: Vec::new(),
            enabled_forwarding: false,
            backend,
            original_ipv4_forward: None,
            original_ipv6_forward: None,
        })
    }

    /// Create a new NAT manager (non-Linux platforms)
    #[cfg(not(target_os = "linux"))]
    pub fn new(_use_nftables: Option<bool>) -> Result<Self> {
        Ok(Self {
            applied_rules: Vec::new(),
            enabled_forwarding: false,
            #[cfg(target_os = "macos")]
            original_ip_forward: None,
            #[cfg(target_os = "windows")]
            original_ip_forward: None,
        })
    }

    /// Get the firewall backend (Linux only)
    #[cfg(target_os = "linux")]
    pub fn backend(&self) -> FirewallBackend {
        self.backend
    }

    /// Enable IP forwarding on the system
    ///
    /// This is required for NAT to work properly.
    ///
    /// # Platform Requirements
    ///
    /// - **Linux**: Writes to `/proc/sys/net/ipv4/ip_forward`
    /// - **macOS**: Uses `sysctl net.inet.ip.forwarding=1`
    /// - **Windows**: Enables IP routing via registry/netsh
    pub fn enable_ip_forwarding(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.enable_ip_forwarding_linux()?;
        }

        #[cfg(target_os = "macos")]
        {
            self.enable_ip_forwarding_macos()?;
        }

        #[cfg(target_os = "windows")]
        {
            self.enable_ip_forwarding_windows()?;
        }

        self.enabled_forwarding = true;
        log::info!("IP forwarding enabled");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn enable_ip_forwarding_linux(&mut self) -> Result<()> {
        use std::fs;

        // Save original IPv4 forwarding value
        if let Ok(value) = fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
            self.original_ipv4_forward = Some(value.trim().to_string());
        }

        // Save original IPv6 forwarding value
        if let Ok(value) = fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding") {
            self.original_ipv6_forward = Some(value.trim().to_string());
        }

        // Enable IPv4 forwarding
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| Error::Nat(format!("failed to enable IPv4 forwarding: {}", e)))?;

        // Enable IPv6 forwarding
        let _ = fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1");

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn enable_ip_forwarding_macos(&mut self) -> Result<()> {
        // Save original forwarding value
        if let Ok(output) = Command::new("sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
        {
            if output.status.success() {
                self.original_ip_forward =
                    Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }
        }

        let output = Command::new("sysctl")
            .args(["-w", "net.inet.ip.forwarding=1"])
            .output()
            .map_err(|e| Error::Nat(format!("failed to run sysctl: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Nat(format!(
                "failed to enable IP forwarding: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn enable_ip_forwarding_windows(&mut self) -> Result<()> {
        // Save original forwarding value from registry
        if let Ok(output) = Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "/v",
                "IPEnableRouter",
            ])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parse registry output to extract the value (format: "IPEnableRouter    REG_DWORD    0x0")
                for line in stdout.lines() {
                    if line.contains("IPEnableRouter") {
                        if let Some(value) = line.split_whitespace().last() {
                            self.original_ip_forward = Some(value.to_string());
                            break;
                        }
                    }
                }
            }
        }

        let output = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "interface",
                "interface=",
                "forwarding=enabled",
            ])
            .output()
            .map_err(|e| Error::Nat(format!("failed to run netsh: {}", e)))?;

        if !output.status.success() {
            // Try alternative method via registry
            let reg_output = Command::new("reg")
                .args([
                    "add",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    "/v",
                    "IPEnableRouter",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "1",
                    "/f",
                ])
                .output()
                .map_err(|e| Error::Nat(format!("failed to modify registry: {}", e)))?;

            if !reg_output.status.success() {
                return Err(Error::Nat("failed to enable IP forwarding".into()));
            }
        }

        Ok(())
    }

    /// Add a NAT/masquerade rule
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hop_tun::nat::{NatManager, NatRule};
    ///
    /// let mut manager = NatManager::new(None)?;  // Auto-detect backend
    /// manager.enable_ip_forwarding()?;
    ///
    /// let rule = NatRule::masquerade("10.0.0.0/24", "eth0");
    /// manager.add_rule(&rule)?;
    /// ```
    pub fn add_rule(&mut self, rule: &NatRule) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.add_rule_linux(rule)?;
        }

        #[cfg(target_os = "macos")]
        {
            self.add_rule_macos(rule)?;
        }

        #[cfg(target_os = "windows")]
        {
            self.add_rule_windows(rule)?;
        }

        self.applied_rules.push(rule.clone());
        log::info!("Added NAT rule: {} -> {}", rule.source, rule.out_interface);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn add_rule_linux(&self, rule: &NatRule) -> Result<()> {
        match self.backend {
            FirewallBackend::Nftables => self.add_rule_nftables(rule),
            FirewallBackend::Iptables => self.add_rule_iptables(rule),
        }
    }

    #[cfg(target_os = "linux")]
    fn add_rule_nftables(&self, rule: &NatRule) -> Result<()> {
        // Create the ruhop table and chains if they don't exist
        // Using 'nft -f -' to execute multiple commands atomically
        let nat_action = if rule.use_snat {
            if let Some(ref addr) = rule.snat_address {
                format!("snat to {}", addr)
            } else {
                return Err(Error::Nat("SNAT requires an address".into()));
            }
        } else {
            "masquerade".to_string()
        };

        // Build nftables script
        let nft_script = format!(
            r#"
table ip {table} {{
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {source} oifname "{oif}" {action}
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        ip saddr {source} oifname "{oif}" accept
        ip daddr {source} ct state related,established accept
    }}
}}
"#,
            table = NFT_TABLE_NAME,
            source = rule.source,
            oif = rule.out_interface,
            action = nat_action,
        );

        // First, delete existing table if present (ignore errors)
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", NFT_TABLE_NAME])
            .output();

        // Apply the new ruleset
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Nat(format!("failed to run nft: {}", e)))?;

        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(nft_script.as_bytes())
                .map_err(|e| Error::Nat(format!("failed to write nft script: {}", e)))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| Error::Nat(format!("failed to run nft: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Nat(format!(
                "nft failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn add_rule_iptables(&self, rule: &NatRule) -> Result<()> {
        let mut args = vec![
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &rule.source,
            "-o",
            &rule.out_interface,
        ];

        let snat_addr_str;
        if rule.use_snat {
            if let Some(ref addr) = rule.snat_address {
                snat_addr_str = addr.to_string();
                args.extend(["-j", "SNAT", "--to-source", &snat_addr_str]);
            } else {
                return Err(Error::Nat("SNAT requires an address".into()));
            }
        } else {
            args.extend(["-j", "MASQUERADE"]);
        }

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .map_err(|e| Error::Nat(format!("failed to run iptables: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Nat(format!(
                "iptables failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Also add FORWARD rules
        let forward_output = Command::new("iptables")
            .args([
                "-A",
                "FORWARD",
                "-s",
                &rule.source,
                "-o",
                &rule.out_interface,
                "-j",
                "ACCEPT",
            ])
            .output()
            .map_err(|e| Error::Nat(format!("failed to add FORWARD rule: {}", e)))?;

        if !forward_output.status.success() {
            log::warn!(
                "Failed to add FORWARD rule: {}",
                String::from_utf8_lossy(&forward_output.stderr)
            );
        }

        // Add reverse FORWARD rule for established connections
        let _ = Command::new("iptables")
            .args([
                "-A",
                "FORWARD",
                "-d",
                &rule.source,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ])
            .output();

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn add_rule_macos(&self, rule: &NatRule) -> Result<()> {
        // macOS uses pf (Packet Filter)
        // We need to create a temporary anchor and load it

        let nat_rule = if rule.use_snat {
            if let Some(ref addr) = rule.snat_address {
                format!(
                    "nat on {} from {} to any -> {}",
                    rule.out_interface, rule.source, addr
                )
            } else {
                return Err(Error::Nat("SNAT requires an address".into()));
            }
        } else {
            format!(
                "nat on {} from {} to any -> ({})",
                rule.out_interface, rule.source, rule.out_interface
            )
        };

        // Write rule to a temporary file
        let rule_file = "/tmp/hop-tun-nat.conf";
        std::fs::write(rule_file, &nat_rule)
            .map_err(|e| Error::Nat(format!("failed to write pf rule: {}", e)))?;

        // Load the rule
        let output = Command::new("pfctl")
            .args(["-ef", rule_file])
            .output()
            .map_err(|e| Error::Nat(format!("failed to run pfctl: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Nat(format!(
                "pfctl failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn add_rule_windows(&self, rule: &NatRule) -> Result<()> {
        // Windows NAT via netsh
        // Note: Windows NAT is more limited than Linux/macOS

        let output = Command::new("netsh")
            .args([
                "routing",
                "ip",
                "nat",
                "add",
                "interface",
                &rule.out_interface,
                "full",
            ])
            .output()
            .map_err(|e| Error::Nat(format!("failed to run netsh: {}", e)))?;

        if !output.status.success() {
            // Try alternative: Windows ICS or Routing and Remote Access
            log::warn!(
                "netsh NAT failed, Windows may require manual NAT configuration: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Remove a NAT rule
    pub fn remove_rule(&mut self, rule: &NatRule) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.remove_rule_linux(rule)?;
        }

        #[cfg(target_os = "macos")]
        {
            self.remove_rule_macos(rule)?;
        }

        #[cfg(target_os = "windows")]
        {
            self.remove_rule_windows(rule)?;
        }

        self.applied_rules.retain(|r| r.source != rule.source);
        log::info!(
            "Removed NAT rule: {} -> {}",
            rule.source,
            rule.out_interface
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_rule_linux(&self, rule: &NatRule) -> Result<()> {
        match self.backend {
            FirewallBackend::Nftables => self.remove_rule_nftables(rule),
            FirewallBackend::Iptables => self.remove_rule_iptables(rule),
        }
    }

    #[cfg(target_os = "linux")]
    fn remove_rule_nftables(&self, _rule: &NatRule) -> Result<()> {
        // Simply delete the entire ruhop table
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", NFT_TABLE_NAME])
            .output();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_rule_iptables(&self, rule: &NatRule) -> Result<()> {
        let mut args = vec![
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            &rule.source,
            "-o",
            &rule.out_interface,
        ];

        let snat_addr_str;
        if rule.use_snat {
            if let Some(ref addr) = rule.snat_address {
                snat_addr_str = addr.to_string();
                args.extend(["-j", "SNAT", "--to-source", &snat_addr_str]);
            }
        } else {
            args.extend(["-j", "MASQUERADE"]);
        }

        let _ = Command::new("iptables").args(&args).output();

        // Remove FORWARD rules
        let _ = Command::new("iptables")
            .args([
                "-D",
                "FORWARD",
                "-s",
                &rule.source,
                "-o",
                &rule.out_interface,
                "-j",
                "ACCEPT",
            ])
            .output();

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn remove_rule_macos(&self, _rule: &NatRule) -> Result<()> {
        // Disable pf or flush rules
        let _ = Command::new("pfctl").args(["-d"]).output();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn remove_rule_windows(&self, rule: &NatRule) -> Result<()> {
        let _ = Command::new("netsh")
            .args([
                "routing",
                "ip",
                "nat",
                "delete",
                "interface",
                &rule.out_interface,
            ])
            .output();
        Ok(())
    }

    /// Clean up all NAT rules and restore IP forwarding to original state
    pub fn cleanup(&mut self) -> Result<()> {
        // Remove all applied rules
        let rules: Vec<NatRule> = self.applied_rules.drain(..).collect();
        for rule in &rules {
            let _ = self.remove_rule(rule);
        }

        // Restore IP forwarding state if we changed it
        if self.enabled_forwarding {
            #[cfg(target_os = "linux")]
            {
                // Restore original IPv4 forwarding value
                if let Some(ref original) = self.original_ipv4_forward {
                    log::debug!("Restoring IPv4 forwarding to original value: {}", original);
                    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", original);
                }
                // Restore original IPv6 forwarding value
                if let Some(ref original) = self.original_ipv6_forward {
                    log::debug!("Restoring IPv6 forwarding to original value: {}", original);
                    let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", original);
                }
            }

            #[cfg(target_os = "macos")]
            {
                // Restore original forwarding value
                if let Some(ref original) = self.original_ip_forward {
                    log::debug!("Restoring IP forwarding to original value: {}", original);
                    let _ = Command::new("sysctl")
                        .args(["-w", &format!("net.inet.ip.forwarding={}", original)])
                        .output();
                }
            }

            #[cfg(target_os = "windows")]
            {
                // Restore original forwarding value via registry
                if let Some(ref original) = self.original_ip_forward {
                    log::debug!("Restoring IP forwarding to original value: {}", original);
                    // Parse the hex value (e.g., "0x0" or "0x1") to decimal
                    let value = if let Some(stripped) = original.strip_prefix("0x") {
                        u32::from_str_radix(stripped, 16).unwrap_or(0)
                    } else {
                        original.parse::<u32>().unwrap_or(0)
                    };
                    let _ = Command::new("reg")
                        .args([
                            "add",
                            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                            "/v",
                            "IPEnableRouter",
                            "/t",
                            "REG_DWORD",
                            "/d",
                            &value.to_string(),
                            "/f",
                        ])
                        .output();
                }
            }

            self.enabled_forwarding = false;
        }

        log::info!("NAT cleanup completed");
        Ok(())
    }

    /// Get the list of applied rules
    pub fn applied_rules(&self) -> &[NatRule] {
        &self.applied_rules
    }
}

impl Drop for NatManager {
    fn drop(&mut self) {
        // Best effort cleanup on drop
        let _ = self.cleanup();
    }
}

/// Helper to set up NAT for a VPN tunnel
///
/// This is a convenience function that:
/// 1. Enables IP forwarding
/// 2. Sets up masquerading for the tunnel network
///
/// # Arguments
/// * `tunnel_network` - The tunnel network in CIDR notation (e.g., "10.0.0.0/24")
/// * `outbound_interface` - The outbound network interface for NAT
/// * `use_nftables` - Firewall backend selection (Linux only):
///   - `Some(true)`: Use nftables
///   - `Some(false)`: Use iptables
///   - `None`: Auto-detect
///
/// # Example
///
/// ```ignore
/// use hop_tun::nat::setup_vpn_nat;
///
/// // Set up NAT for traffic from 10.0.0.0/24 going out via eth0
/// let mut nat = setup_vpn_nat("10.0.0.0/24", "eth0", None)?;
///
/// // ... VPN running ...
///
/// // Cleanup happens automatically on drop, or call:
/// nat.cleanup()?;
/// ```
pub fn setup_vpn_nat(
    tunnel_network: &str,
    outbound_interface: &str,
    use_nftables: Option<bool>,
) -> Result<NatManager> {
    let mut manager = NatManager::new(use_nftables)?;

    manager.enable_ip_forwarding()?;

    let rule = NatRule::masquerade(tunnel_network, outbound_interface);
    manager.add_rule(&rule)?;

    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_rule_masquerade() {
        let rule = NatRule::masquerade("10.0.0.0/24", "eth0");
        assert_eq!(rule.source, "10.0.0.0/24");
        assert_eq!(rule.out_interface, "eth0");
        assert!(!rule.use_snat);
    }

    #[test]
    fn test_nat_rule_snat() {
        let rule = NatRule::snat("10.0.0.0/24", "eth0", "192.168.1.1".parse().unwrap());
        assert!(rule.use_snat);
        assert!(rule.snat_address.is_some());
    }

    #[test]
    fn test_nat_manager_creation() {
        // On non-Linux or when firewall tools are available, this should work
        if let Ok(manager) = NatManager::new(None) {
            assert!(manager.applied_rules().is_empty());
        }
        // On systems without firewall tools, new() returns an error, which is expected
    }
}
