//! NAT/Masquerading setup for TUN devices
//!
//! This module provides functionality to set up NAT (Network Address Translation)
//! and IP masquerading for traffic flowing through TUN interfaces.
//!
//! # Platform Support
//!
//! - **Linux**: Uses iptables/nftables for NAT configuration
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
}

impl NatManager {
    /// Create a new NAT manager
    pub fn new() -> Self {
        Self {
            applied_rules: Vec::new(),
            enabled_forwarding: false,
        }
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
    fn enable_ip_forwarding_linux(&self) -> Result<()> {
        use std::fs;

        // Enable IPv4 forwarding
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| Error::Nat(format!("failed to enable IPv4 forwarding: {}", e)))?;

        // Enable IPv6 forwarding
        let _ = fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1");

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn enable_ip_forwarding_macos(&self) -> Result<()> {
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
    fn enable_ip_forwarding_windows(&self) -> Result<()> {
        let output = Command::new("netsh")
            .args(["interface", "ipv4", "set", "interface", "interface=", "forwarding=enabled"])
            .output()
            .map_err(|e| Error::Nat(format!("failed to run netsh: {}", e)))?;

        if !output.status.success() {
            // Try alternative method via registry
            let reg_output = Command::new("reg")
                .args([
                    "add",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    "/v", "IPEnableRouter",
                    "/t", "REG_DWORD",
                    "/d", "1",
                    "/f"
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
    /// let mut manager = NatManager::new();
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
        let mut args = vec![
            "-t", "nat",
            "-A", "POSTROUTING",
            "-s", &rule.source,
            "-o", &rule.out_interface,
        ];

        if rule.use_snat {
            if let Some(ref addr) = rule.snat_address {
                args.extend(["-j", "SNAT", "--to-source", &addr.to_string()]);
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
                "-A", "FORWARD",
                "-s", &rule.source,
                "-o", &rule.out_interface,
                "-j", "ACCEPT"
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
                "-A", "FORWARD",
                "-d", &rule.source,
                "-m", "state",
                "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT"
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
                "routing", "ip", "nat", "add", "interface",
                &rule.out_interface,
                "full"
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
        log::info!("Removed NAT rule: {} -> {}", rule.source, rule.out_interface);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_rule_linux(&self, rule: &NatRule) -> Result<()> {
        let mut args = vec![
            "-t", "nat",
            "-D", "POSTROUTING",
            "-s", &rule.source,
            "-o", &rule.out_interface,
        ];

        if rule.use_snat {
            if let Some(ref addr) = rule.snat_address {
                args.extend(["-j", "SNAT", "--to-source", &addr.to_string()]);
            }
        } else {
            args.extend(["-j", "MASQUERADE"]);
        }

        let _ = Command::new("iptables").args(&args).output();

        // Remove FORWARD rules
        let _ = Command::new("iptables")
            .args([
                "-D", "FORWARD",
                "-s", &rule.source,
                "-o", &rule.out_interface,
                "-j", "ACCEPT"
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
                "routing", "ip", "nat", "delete", "interface",
                &rule.out_interface
            ])
            .output();
        Ok(())
    }

    /// Clean up all NAT rules and disable IP forwarding if we enabled it
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
                let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "0");
            }

            #[cfg(target_os = "macos")]
            {
                let _ = Command::new("sysctl")
                    .args(["-w", "net.inet.ip.forwarding=0"])
                    .output();
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

impl Default for NatManager {
    fn default() -> Self {
        Self::new()
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
/// # Example
///
/// ```ignore
/// use hop_tun::nat::setup_vpn_nat;
///
/// // Set up NAT for traffic from 10.0.0.0/24 going out via eth0
/// let mut nat = setup_vpn_nat("10.0.0.0/24", "eth0")?;
///
/// // ... VPN running ...
///
/// // Cleanup happens automatically on drop, or call:
/// nat.cleanup()?;
/// ```
pub fn setup_vpn_nat(
    tunnel_network: &str,
    outbound_interface: &str,
) -> Result<NatManager> {
    let mut manager = NatManager::new();

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
        let rule = NatRule::snat(
            "10.0.0.0/24",
            "eth0",
            "192.168.1.1".parse().unwrap(),
        );
        assert!(rule.use_snat);
        assert!(rule.snat_address.is_some());
    }

    #[test]
    fn test_nat_manager_creation() {
        let manager = NatManager::new();
        assert!(manager.applied_rules().is_empty());
        assert!(!manager.enabled_forwarding);
    }
}
