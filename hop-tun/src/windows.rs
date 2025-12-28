//! Windows-specific TUN device functionality
//!
//! Windows TUN support requires the WinTun driver to be installed.
//! Download from: https://www.wintun.net/
//!
//! This module provides Windows-specific extensions and utilities.
//!
//! Note: Route management is handled by the `route` module using `net-route`.
//! This module provides Windows-specific utilities that complement the core functionality.

use std::process::Command;

use crate::error::{Error, Result};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Check if WinTun driver is installed
pub fn is_wintun_installed() -> bool {
    // Check for wintun.dll in system32 or alongside the executable
    let system_path = std::path::Path::new(r"C:\Windows\System32\wintun.dll");
    let local_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")));

    system_path.exists() || local_path.is_some_and(|p| p.exists())
}

/// Get the path to wintun.dll
pub fn get_wintun_path() -> Option<std::path::PathBuf> {
    // First check local directory
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let local_path = dir.join("wintun.dll");
            if local_path.exists() {
                return Some(local_path);
            }
        }
    }

    // Then check system32
    let system_path = std::path::PathBuf::from(r"C:\Windows\System32\wintun.dll");
    if system_path.exists() {
        return Some(system_path);
    }

    None
}

/// Get network adapter information using netsh
#[derive(Debug, Clone)]
pub struct AdapterInfo {
    pub name: String,
    pub description: String,
    pub mac_address: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Vec<String>,
    pub status: String,
}

/// List all network adapters
pub fn list_adapters() -> Result<Vec<AdapterInfo>> {
    let output = Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output()
        .map_err(|e| Error::NotSupported(format!("failed to run netsh: {}", e)))?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut adapters = Vec::new();

    for line in output_str.lines().skip(3) {
        // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            adapters.push(AdapterInfo {
                name: parts[3..].join(" "),
                description: String::new(),
                mac_address: None,
                ipv4: None,
                ipv6: Vec::new(),
                status: parts[0].to_string(),
            });
        }
    }

    Ok(adapters)
}

/// Get adapter details
pub fn get_adapter_info(name: &str) -> Result<AdapterInfo> {
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "show", "addresses", name])
        .output()
        .map_err(|e| Error::DeviceNotFound(format!("{}: {}", name, e)))?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut info = AdapterInfo {
        name: name.to_string(),
        description: String::new(),
        mac_address: None,
        ipv4: None,
        ipv6: Vec::new(),
        status: "Unknown".to_string(),
    };

    for line in output_str.lines() {
        let line = line.trim();
        if line.starts_with("IP Address:") {
            info.ipv4 = line
                .strip_prefix("IP Address:")
                .map(|s| s.trim().to_string());
        }
    }

    Ok(info)
}

/// Configure adapter IP address using netsh
pub fn configure_adapter_address(
    name: &str,
    address: &str,
    mask: &str,
    gateway: Option<&str>,
) -> Result<()> {
    let mut args = vec![
        "interface",
        "ipv4",
        "set",
        "address",
        name,
        "static",
        address,
        mask,
    ];

    if let Some(gw) = gateway {
        args.push(gw);
    }

    let output = Command::new("netsh")
        .args(&args)
        .output()
        .map_err(|e| Error::Config(format!("failed to configure adapter: {}", e)))?;

    if !output.status.success() {
        return Err(Error::Config(format!(
            "netsh failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Set adapter MTU
pub fn set_adapter_mtu(name: &str, mtu: u32) -> Result<()> {
    let output = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            name,
            &format!("mtu={}", mtu),
            "store=persistent",
        ])
        .output()
        .map_err(|e| Error::Config(format!("failed to set MTU: {}", e)))?;

    if !output.status.success() {
        return Err(Error::Config(format!(
            "netsh failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Enable/disable Windows Firewall for an interface
pub fn configure_firewall(interface: &str, enable: bool) -> Result<()> {
    let action = if enable { "enable" } else { "disable" };

    let _output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "set",
            "rule",
            &format!("name=\"Allow {} Traffic\"", interface),
            &format!("new enable={}", if enable { "yes" } else { "no" }),
        ])
        .output();

    // If rule doesn't exist, create it
    if enable {
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name=Allow {} Traffic", interface),
                "dir=in",
                "action=allow",
                &format!("interface=\"{}\"", interface),
            ])
            .output();
    }

    log::info!("Firewall {} for {}", action, interface);
    Ok(())
}

/// Configure Windows Firewall to allow VPN UDP traffic
/// This adds firewall rules to allow inbound/outbound UDP traffic for the VPN
pub fn configure_vpn_firewall(app_name: &str, enable: bool) -> Result<()> {
    let rule_name_in = format!("{} VPN Inbound", app_name);
    let rule_name_out = format!("{} VPN Outbound", app_name);

    if enable {
        // Get the path to our executable
        let exe_path = std::env::current_exe()
            .map_err(|e| Error::Config(format!("failed to get executable path: {}", e)))?;
        let exe_path_str = exe_path.to_string_lossy();

        // Remove existing rules first (ignore errors)
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name_in),
            ])
            .output();
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name_out),
            ])
            .output();

        // Add inbound rule for UDP
        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", rule_name_in),
                "dir=in",
                "action=allow",
                "protocol=UDP",
                &format!("program={}", exe_path_str),
                "enable=yes",
            ])
            .output()
            .map_err(|e| Error::Config(format!("failed to add firewall rule: {}", e)))?;

        if !output.status.success() {
            log::warn!(
                "Failed to add inbound firewall rule: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            log::info!("Added firewall rule: {}", rule_name_in);
        }

        // Add outbound rule for UDP
        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", rule_name_out),
                "dir=out",
                "action=allow",
                "protocol=UDP",
                &format!("program={}", exe_path_str),
                "enable=yes",
            ])
            .output()
            .map_err(|e| Error::Config(format!("failed to add firewall rule: {}", e)))?;

        if !output.status.success() {
            log::warn!(
                "Failed to add outbound firewall rule: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            log::info!("Added firewall rule: {}", rule_name_out);
        }
    } else {
        // Remove the rules
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name_in),
            ])
            .output();
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", rule_name_out),
            ])
            .output();
        log::info!("Removed firewall rules for {}", app_name);
    }

    Ok(())
}

/// Check if running with administrator privileges using Windows API
pub fn is_admin() -> bool {
    unsafe {
        let mut token_handle: HANDLE = std::ptr::null_mut();
        let process_handle = GetCurrentProcess();

        if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        CloseHandle(token_handle);

        result != 0 && elevation.TokenIsElevated != 0
    }
}

/// Request UAC elevation by relaunching the current process with "runas"
/// Returns Ok(true) if elevation was requested (process will exit)
/// Returns Ok(false) if already elevated
/// Returns Err if elevation failed
pub fn request_elevation() -> Result<bool> {
    if is_admin() {
        return Ok(false);
    }

    // Get the current executable path and arguments
    let exe_path = std::env::current_exe()
        .map_err(|e| Error::PermissionDenied(format!("Failed to get executable path: {}", e)))?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_str = args.join(" ");

    // Use PowerShell Start-Process with -Verb RunAs for UAC elevation
    let status = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs",
                exe_path.display(),
                args_str.replace("'", "''") // Escape single quotes
            ),
        ])
        .status()
        .map_err(|e| Error::PermissionDenied(format!("Failed to request elevation: {}", e)))?;

    if status.success() {
        Ok(true) // Elevation requested, caller should exit
    } else {
        Err(Error::PermissionDenied(
            "User declined elevation or elevation failed".into(),
        ))
    }
}

/// Check admin privileges and request elevation if needed
/// Returns Ok(()) if running as admin or elevation was declined
/// The caller should check is_admin() after this to determine if operations should proceed
pub fn ensure_admin() -> Result<()> {
    if is_admin() {
        return Ok(());
    }

    Err(Error::PermissionDenied(
        "Administrator privileges required. Please run as Administrator.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wintun_check() {
        // This just verifies the function doesn't panic
        let _ = is_wintun_installed();
    }
}
